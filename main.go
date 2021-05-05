package main

import (
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	SESSION_ID  = "test"
	SESSION_KEY = "secretkey123"

	CSRFKey         = "csrf"
	CSRFTokenHeader = "X-CSRF-Token"

	username = "kreditplus123"
	password = "rahasia"
)

var JwtSecret = []byte("secretkey")
var store = sessions.NewCookieStore([]byte(SESSION_KEY))

func middlewareOne(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		fmt.Println("proses middleware one!")
		// business logic here
		return next(c)
	}
}

func middlewareTwo(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		fmt.Println("proses middleware two!")
		// business logic here
		return next(c)
	}
}

func externalMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("proses external middleware")
		next.ServeHTTP(w, r)
	})
}

func makeLogEntry(c echo.Context) *log.Entry {
	log.SetFormatter(&log.JSONFormatter{})
	if c == nil {
		return log.WithFields(log.Fields{
			"at": time.Now().Format("2006-01-02 15:04:05"),
		})
	}
	return log.WithFields(log.Fields{
		"at":     time.Now().Format("2006-01-02 15:04:05"),
		"method": c.Request().Method,
		"uri":    c.Request().URL.String(),
		"ip":     c.Request().RemoteAddr,
	})
}

func middlewareLogrus(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		makeLogEntry(c).Info("incoming request")
		return next(c)
	}
}

// GetDataFromClaims ..
func GetDataFromClaims(key string, claims jwt.Claims) reflect.Value {
	fmt.Println("CLAIMS => ", claims)
	v := reflect.ValueOf(claims)
	if v.Kind() == reflect.Map {
		for _, k := range v.MapKeys() {
			value := v.MapIndex(k)

			if fmt.Sprintf("%s", k.Interface()) == key {
				return value
			}
		}
	}
	return reflect.Value{}
}

func middlewareValidJWT(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		auth := c.Request().Header.Get("Authorization")
		bearer := strings.HasPrefix(auth, "Bearer ")
		if !bearer {
			return c.String(http.StatusUnauthorized, "Invalid permission")
		}

		authSplit := strings.Split(auth, " ")
		if len(authSplit) < 2 {
			return c.String(http.StatusUnauthorized, "Invalid permission")
		}

		t, err := jwt.Parse(authSplit[1], func(*jwt.Token) (interface{}, error) {
			return JwtSecret, nil
		})
		if err != nil {
			fmt.Println("Failed to parse token to jwt: ", err)
			return c.String(http.StatusUnauthorized, "Invalid permission")
		}

		// claimPermission := utils.GetDataFromClaims("permissions", t.Claims)
		claimUsername := GetDataFromClaims("username", t.Claims)
		claimExp := GetDataFromClaims("exp", t.Claims)
		if claimExp.Interface().(float64) <= float64(time.Now().Unix()) {
			return c.String(http.StatusUnauthorized, "jwt expired")
		}
		if claimUsername.Interface().(string) == "" {
			return c.String(http.StatusUnauthorized, "Invalid permission")
		}

		// get data by role from db
		// data role from db di check dengan request urlnya

		// fmt.Println("Request Transaction by: ", claimUsername.Interface().(string))

		return c.String(http.StatusUnauthorized, "Invalid permission")

	}
}

// GenerateToken ..
func GenerateToken(username string) (string, error) {

	type Claims struct {
		Username string `json:"username,omitempty"`
		jwt.StandardClaims
	}

	nowTime := time.Now()
	expireTime := nowTime.Add(time.Duration(20) * time.Second)
	expiredAt := expireTime.Unix()
	claims := Claims{
		username,
		jwt.StandardClaims{
			ExpiresAt: expiredAt,
		},
	}

	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwt.New(jwt.SigningMethodHS256)
	token, err := tokenClaims.SignedString(JwtSecret)
	return token, err
}

func main() {

	port := *flag.String("port", ":8080", "config port")
	fmt.Println(port)

	tmpl := template.Must(template.ParseGlob("./*.html"))
	e := echo.New()

	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetConfigName("config.json")
	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("error init config: ", err)
		return
	}

	// e.Use(middleware.CORS())
	// e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
	// 	TokenLookup: "header:" + CSRFTokenHeader,
	// 	ContextKey:  CSRFKey,
	// }))

	// e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
	// 	Format: "method=${method}, uri=${uri}, status=${status}\n",
	// }))
	// e.Use(middleware.Logger())
	e.Use(middlewareLogrus)

	e.POST("/login", func(c echo.Context) error {
		fmt.Println("test")
		data := make(map[string]string)
		if err := c.Bind(&data); err != nil {
			fmt.Println("Error: ", err)

			return c.String(http.StatusBadRequest, err.Error())
		}

		if data["username"] != username || data["password"] != password {
			fmt.Println("username salah")

			return c.String(http.StatusBadRequest, "username / password salah")
		}

		token, err := GenerateToken(data["username"])
		if err != nil {
			fmt.Println("Error generate token: ", err)
		}

		return c.String(http.StatusOK, token)
		// session, err := store.Get(c.Request(), SESSION_ID)
		// if err != nil {
		// 	fmt.Println("Something error with: ", err)
		// }
		// session.Values["username"] = "dicky"
		// session.Values["password"] = "encrypt(example123)"
		// session.Values["token"] = "jwt"
		// session.Save(c.Request(), c.Response())

		// return c.Redirect(http.StatusTemporaryRedirect, "/dashboard")

	})

	user := e.Group("/user")
	user.Use(middlewareOne)
	user.Use(middlewareTwo)
	user.Use(echo.WrapMiddleware(externalMiddleware))
	user.GET("/index", func(c echo.Context) error {
		data := make(map[string]interface{})
		data[CSRFKey] = c.Get(CSRFKey)
		return tmpl.Execute(c.Response(), data)
	})

	// localhost:8080/transaction

	user.GET("/getCsrfToken", func(c echo.Context) error {
		// validasi jwt 20line
		// data := make(map[string]interface{})
		// data[CSRFKey] = c.Get(CSRFKey)
		return c.String(http.StatusOK, c.Get(CSRFKey).(string))
	})

	user.POST("/sayHello", func(c echo.Context) error {
		data := make(map[string]interface{})
		if err := c.Bind(&data); err != nil {
			return err
		}
		message := fmt.Sprintf("hello %s", data["name"])
		return c.JSON(http.StatusOK, message)
	})

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	}, middlewareValidJWT)

	e.GET("/dashboard", func(c echo.Context) error {
		session, err := store.Get(c.Request(), SESSION_ID)
		if err != nil {
			fmt.Println("Something error with: ", err)
		}
		if len(session.Values) == 0 {
			return c.String(http.StatusUnauthorized, "Session is empty")
		}

		// EXAMPLE: pengecheckan payload jwt, lalu dicompare dengan data dari header

		return c.String(http.StatusOK, fmt.Sprintf("%s - %s", session.Values["username"], session.Values["password"]))
	})

	e.GET("/logout", func(c echo.Context) error {
		session, err := store.Get(c.Request(), SESSION_ID)
		if err != nil {
			fmt.Println("Something error with: ", err)
		}
		if len(session.Values) == 0 {
			return c.String(http.StatusUnauthorized, "Session is empty")
		}
		session.Options.MaxAge = -1
		session.Save(c.Request(), c.Response())
		return c.String(http.StatusOK, "logout sukses")
	})

	e.Start(os.Getenv("APP_PORT"))
}

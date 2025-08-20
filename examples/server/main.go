package main

import (
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/ghettovoice/gosip"

	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/transport"
)

var (
	logger log.Logger
)

func init() {
	logger = log.NewDefaultLogrusLogger().WithPrefix("Server")
}

var Users = map[string]string{}

func main() {

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	srvConf := gosip.ServerConfig{}
	srv := gosip.NewServer(srvConf, nil, nil, logger)

	// Регистрация обработчика для REGISTER
	if err := srv.OnRequest(sip.REGISTER, registerHandler()); err != nil {
		logger.Fatalf("Ошибка регистрации обработчика: %v", err)
	}
	// Регистрация обработчика для INVITE
	if err := srv.OnRequest(sip.INVITE, inviteHandler()); err != nil {
		logger.Fatalf("Ошибка регистрации обработчика: %v", err)
	}

	// Регистрация обработчика для PUBLISH
	if err := srv.OnRequest(sip.PUBLISH, publishHandler()); err != nil {
		logger.Fatalf("Ошибка регистрации обработчика: %v", err)
	}

	// Запуск сервера
	if err := srv.Listen("udp", "0.0.0.0:5060", &transport.TLSConfig{Cert: "certs/cert.pem", Key: "certs/key.pem"}); err != nil {
		logger.Fatalf("Ошибка запуска сервера: %v", err)
	}

	<-stop
	// Отправка уведомлений
	notifyUnregistration()

	// Остановка сервера
	srv.Shutdown()
}

// Обработчик для PUBLISH
func publishHandler() gosip.RequestHandler {
	return func(req sip.Request, tx sip.ServerTransaction) {
		from, _ := req.From()
		logger.Debugf("Получен PUBLISH-запрос от %s", from)

		// Простой ответ 200 OK
		res := sip.NewResponseFromRequest("", req, 200, "OK", "")
		if err := tx.Respond(res); err != nil {
			logger.Errorf("Ошибка отправки ответа: %v", err)
		}
	}
}
func registerHandler() gosip.RequestHandler {
	return func(req sip.Request, tx sip.ServerTransaction) {
		logger.Debugf("Получен запрос от %s", req)
		from, _ := req.From()
		username := extractUsername(from.Address)

		// Проверка на разрегистрацию (Expires: 0)
		expiresHeader := req.GetHeaders("Expires")
		var expires int
		if expiresHeader != nil {
			expiresStr := expiresHeader[0].Value()
			if val, err := strconv.Atoi(expiresStr); err == nil {
				expires = val
			}
		}

		// Если Expires: 0 — удаляем пользователя
		if expires == 0 {
			logger.Infof("Разрегистрация пользователя %s", username)
			delete(Users, username)
			res := sip.NewResponseFromRequest("", req, 200, "OK", "")
			if err := tx.Respond(res); err != nil {
				logger.Errorf("Ошибка отправки ответа: %v", err)
			}
			return
		}

		// Обычная регистрация
		contactHeader, _ := req.Contact()
		if contactHeader != nil {
			contactURI := contactHeader.Address
			Users[username] = contactURI.String()
			logger.Infof("Зарегистрирован пользователь %s с адресом %s", username, contactURI)
		}

		res := sip.NewResponseFromRequest("", req, 200, "OK", "")
		if err := tx.Respond(res); err != nil {
			logger.Errorf("Ошибка отправки ответа: %v", err)
		}
	}
}

func inviteHandler() gosip.RequestHandler {
	return func(req sip.Request, tx sip.ServerTransaction) {
		from, _ := req.From()
		to, _ := req.To()
		username := extractUsername(to.Address)

		// Поиск зарегистрированного адреса
		target, ok := Users[username]
		if !ok {
			res := sip.NewResponseFromRequest("", req, 404, "Not Found", "")
			if err := tx.Respond(res); err != nil {
				logger.Errorf("Ошибка отправки ответа: %v", err)
			}
			return
		}

		logger.Infof("Перенаправление вызова на %s", target)

		// Отправка INVITE зарегистрированному пользователю
		res := sip.NewResponseFromRequest("", req, 302, "Moved Temporarily", "")
		res.AppendHeader(&sip.ContactHeader{
			Address: from.Address,
		})
		if err := tx.Respond(res); err != nil {
			logger.Errorf("Ошибка отправки ответа: %v", err)
		}
	}
}

func extractUsername(uri sip.Uri) string {
	user := uri.User().String()
	if user == "" {
		return ""
	}
	parts := strings.Split(user, "@")
	logger.Debugf("parts: %v", parts)
	return parts[0]
}

func notifyUnregistration() {
	logger.Infof("Отправка уведомлений о разрегистрации всем пользователям")

	for username, contactURI := range Users {
		// Извлечение URI из строки (без ParseUri)
		parts := strings.Split(contactURI, "@")
		if len(parts) < 2 {
			continue
		}

		hostPort := parts[1]
		hostPortParts := strings.Split(hostPort, ";")
		hostPort = hostPortParts[0]

		host, portStr, err := net.SplitHostPort(hostPort)
		if err != nil {
			logger.Errorf("Ошибка разбора URI: %v", err)
			continue
		}

		port, _ := strconv.Atoi(portStr)

		// Создание нового URI
		uri := NewSipUri()

		// Установка параметров
		uri.Scheme = "sip"
		uri.Host = "example.com"
		uri.Port = "5060"
		serverName := MaybeString{Value: "ServerName"}
		// Использование URI
		address := sip.Address{
			URI:         uri,
			DisplayName: serverName,
		}
		// Создание фиктивного запроса
		from := sip.Address{
			Uri:         uri,
			DisplayName: serverName,
		}

		to := sip.Address{
			Uri: sip.Uri{
				Scheme: "sip",
				User:   username,
				Host:   host,
				Port:   port,
			},
		}

		// Создание запроса
		req := sip.NewRequest(
			sip.MESSAGE,
			to.URI,
			&sip.FromHeader{Address: from},
			&sip.ToHeader{Address: to},
			nil,
		)

		// Формирование ответа
		res := sip.NewResponseFromRequest("Server", req, 481, "Call/Transaction Does Not Exist", "")
		logger.Infof("Отправлено уведомление пользователю %s", username)
	}

	// Очистка списка пользователей
	Users = make(map[string]string)
}

type SipUri struct {
	Scheme string
	User   sip.MaybeString
	Host   string
	Port   *Port
}

func NewSipUri() *SipUri {
	return &SipUri{}
}

type MaybeString struct {
	Value string
	Set   bool
}

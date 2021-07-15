package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ma5ksh0w/proto-example/internal/app"
	"github.com/spf13/pflag"
)

var (
	name       string
	listenAddr string
)

func main() {
	pflag.StringVarP(&name, "name", "n", "User", "Имя пользователя")
	pflag.StringVarP(&listenAddr, "listen", "l", "127.0.0.1:3030", "Адрес клиента")
	pflag.Parse()

	c, err := app.New(name, listenAddr, func(from, msg string) {
		fmt.Println("Принято сообщение от", from, ":", msg)
	})

	if err != nil {
		panic(err)
	}

	defer c.Close()

	r := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Введите команду:")
		line, _, err := r.ReadLine()
		if err != nil {
			panic(err)
		}

		if string(line) == "" {
			continue
		}

		parts := strings.SplitN(strings.TrimSpace(string(line)), " ", 3)
		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "?", "помощь":
			fmt.Println("помощь: список команд")
			fmt.Println("сессии: список сессий")
			fmt.Println("отправить [ID] [Сообщение]: отправить сообщение")
			fmt.Println("подключить [Адрес]: соединится с указанным адресом")

		case "отправить":
			if len(parts) < 3 {
				fmt.Println("Неправильная команда")
				fmt.Println("отправить [ID] [Сообщение]: отправить сообщение")
			} else {
				if err := c.SendMessageTo(parts[1], parts[2]); err != nil {
					fmt.Println("Error: " + err.Error())
				}
			}

		case "подлключить":
			if len(parts) < 3 {
				fmt.Println("Неправильная команда")
				fmt.Println("отправить [ID] [Сообщение]: отправить сообщение")
			} else {
				if err := c.SendMessageTo(parts[1], parts[2]); err != nil {
					fmt.Println("Error: " + err.Error())
				}
			}

		case "выход":
			return

		case "сессии":
			list := c.Sessions()
			for _, id := range list {
				fmt.Println(id)
			}

		default:
			fmt.Println("Неправильная команда")
			fmt.Println("помощь: список команд")
			fmt.Println("сессии: список сессий")
			fmt.Println("отправить [ID] [Сообщение]: отправить сообщение")
			fmt.Println("подключить [Адрес]: соединится с указанным адресом")
		}
	}
}

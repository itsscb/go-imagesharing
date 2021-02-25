package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"text/template"
)

var tpl *template.Template
var images []string
var users []user

type user struct {
	Username string
	Password string
}

func main() {
	/*
		users = []user{
			user{
				Username: "dennisp",
				Password: "hÄberle#0815",
			},
			user{
				Username: "brigittes",
				Password: "nAnA#1990",
			},
			user{
				Username: "veronikam",
				Password: "tAnteV#1990",
			},
			user{
				Username: "matthiasm",
				Password: "c0usinX!",
			},
		}
		fmt.Println("\nusers: ", users)
		j, _ := json.Marshal(users)
		fmt.Println(string(j))
		_ = ioutil.WriteFile("users.json", j, 0644)
	*/

	usersFile, err := os.Open("users.json")
	if err != nil {
		fmt.Println(err)
	}

	jsonParser := json.NewDecoder(usersFile)
	if err = jsonParser.Decode(&users); err != nil {
		fmt.Println(err)
	}
	fmt.Println(users)

	fs := http.FileServer(http.Dir("./public/"))
	http.Handle("/public/", http.StripPrefix("/public/", fs))
	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", login)
	http.HandleFunc("/download", download)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":8080", nil)
}

func init() {
	tpl = template.Must(template.ParseGlob("templates/*.gohtml"))
}

func login(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("logged-in")
	if err == http.ErrNoCookie {
		cookie = &http.Cookie{
			Name:     "logged-in",
			Value:    "0",
			HttpOnly: true,
		}
	}

	if req.Method == "POST" {
		password := req.FormValue("password")
		username := req.FormValue("username")
		for _, u := range users {
			if password == u.Password && username == u.Username {
				cookie = &http.Cookie{
					Name:     "logged-in",
					Value:    "1",
					HttpOnly: true,
				}
			}
		}
	}

	if req.URL.Path == "/logout" {
		cookie = &http.Cookie{
			Name:     "logged-in",
			Value:    "0",
			MaxAge:   -1,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, req, "/login", 303)
		return
	}

	http.SetCookie(w, cookie)

	if cookie.Value == "0" {
		err = tpl.ExecuteTemplate(w, "login.gohtml", nil)
		if err != nil {
			http.Error(w, err.Error(), 500)
			fmt.Println(err)
		}
	}

	if cookie.Value == "1" {
		http.Redirect(w, req, "/", 303)
	}

}

func index(w http.ResponseWriter, req *http.Request) {

	cookie, err := req.Cookie("logged-in")
	if err == http.ErrNoCookie {
		cookie = &http.Cookie{
			Name:     "logged-in",
			Value:    "0",
			HttpOnly: true,
		}
	}
	if cookie.Value == "0" {
		http.Redirect(w, req, "/login", 303)
	}

	files, err := ioutil.ReadDir("public/img")
	if err != nil {
		fmt.Println(err)
	}

	err = req.ParseForm()
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, x := range req.Form {
		for i, y := range x {
			fmt.Println("\n"+fmt.Sprint(i), y)
			images = append(images, y) //("public/img/" + y))
		}
	}

	if len(images) >= 1 {
		http.Redirect(w, req, "/download", 303)
	}

	err = tpl.ExecuteTemplate(w, "index.gohtml", files)
	if err != nil {
		http.Error(w, err.Error(), 500)
		fmt.Println(err)
	}
}

func download(w http.ResponseWriter, req *http.Request) {
	output := "temp.zip"
	if err := zipFiles(output, images); err != nil {
		fmt.Println(err)
	}
	images = nil
	http.Redirect(w, req, "/", 303)
}

func zipFiles(filename string, files []string) error {

	newZipFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()
	err = os.Chdir("public/img")
	if err != nil {
		fmt.Println(err)
	}
	// Add files to zip
	for _, file := range files {
		if err = addFileToZip(zipWriter, file); err != nil {
			return err
		}
	}
	err = os.Chdir("../..")
	if err != nil {
		fmt.Println(err)
	}
	return nil
}

func addFileToZip(zipWriter *zip.Writer, filename string) error {

	fileToZip, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fileToZip.Close()

	// Get the file information
	info, err := fileToZip.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}

	// Using FileInfoHeader() above only uses the basename of the file. If we want
	// to preserve the folder structure we can overwrite this with the full path.
	header.Name = filename

	// Change to deflate to gain better compression
	// see http://golang.org/pkg/archive/zip/#pkg-constants
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, fileToZip)
	return err
}

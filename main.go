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

	uuid "github.com/satori/go.uuid"
)

var tpl *template.Template
var images []string
var jusers []user

var users = make(map[string]*user)
var files []os.FileInfo

type user struct {
	Username string
	Password string
	Session  string
	Files    []os.FileInfo
}

func copy(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}
func startSession(u *user) {
	path := "public/" + u.Session + "/"
	x, err := os.Stat(path)
	if os.IsNotExist(err) {
		err = os.Mkdir(path, 0755)
		fmt.Println(err)
	}
	fmt.Println(x, err)
	/*
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			err = os.Mkdir(path, 0755)
			fmt.Println(err)
		}
		for _, f := range files {
			u.Files = append(u.Files, f)
			src := "/public/img/" + f.Name()

			source, err := os.Open(src)
			if err != nil {
				fmt.Println(err)
			}
			defer source.Close()

			destination, err := os.Create(path)
			if err != nil {
				fmt.Println(err)
			}
			defer destination.Close()
			_, err = io.Copy(destination, source)
			if err != nil {
				fmt.Println(err)
			}
		}
	*/
	for _, f := range files {
		copy("public/img/"+f.Name(), path+f.Name())
		u.Files = append(u.Files, f)
	}
}

func main() {

	var err error
	files, err = ioutil.ReadDir("public/img")
	if err != nil {
		fmt.Println(err)
	}

	usersFile, err := os.Open("users.json")
	if err != nil {
		fmt.Println(err)
	}

	jsonParser := json.NewDecoder(usersFile)
	if err = jsonParser.Decode(&jusers); err != nil {
		fmt.Println(err)
	}
	fmt.Println(jusers)
	for _, u := range jusers {
		users[u.Username] = &user{
			Username: u.Username,
			Password: u.Password,
			Session:  "0",
			Files:    nil,
		}
	}

	//fmt.Println(users["brigittes"])

	fsp := http.FileServer(http.Dir("./public/"))
	http.Handle("/public/", http.StripPrefix("/public/", fsp))
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
	cookie, err := req.Cookie("session-id")
	nid, _ := uuid.NewV4()
	if err == http.ErrNoCookie {

		cookie = &http.Cookie{
			Name:  "session-id",
			Value: nid.String(),
			// Secure: true,
			HttpOnly: true,
		}
	}
	/*
		cookie, err := req.Cookie("logged-in")
		if err == http.ErrNoCookie {
			cookie = &http.Cookie{
				Name:  "logged-in",
				Value: "0",
				// Secure: true,
				HttpOnly: true,
			}
		}
	*/
	if req.Method == "POST" {
		password := req.FormValue("password")
		username := req.FormValue("username")
		for _, u := range users {
			if password == u.Password && username == u.Username {
				cookie, err := req.Cookie("session-id")
				if err != nil {
					cookie = &http.Cookie{
						Name:  "session-id",
						Value: nid.String(),
						// Secure: true,
						HttpOnly: true,
					}

				}
				users[u.Username].Session = cookie.Value
				http.SetCookie(w, cookie)
				startSession(u)

				/*
					cookie = &http.Cookie{
						Name:  "session-id",
						Value: "1",
						// Secure: true,
						HttpOnly: true,
					}
				*/

			}

		}
	}
	//fmt.Println(users)
	if req.URL.Path == "/logout" {
		cookie = &http.Cookie{
			Name:   "session-id",
			Value:  "0",
			MaxAge: -1,
			// Secure: true,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, req, "/login", 303)
		return
	}

	for _, u := range users {
		if cookie.Value == u.Session {
			http.Redirect(w, req, "/", 303)
			return
		}
	}

	err = tpl.ExecuteTemplate(w, "login.gohtml", nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		fmt.Println(err)
	}
	return

}

func index(w http.ResponseWriter, req *http.Request) {
	/*
		cookie, err := req.Cookie("logged-in")
		if err == http.ErrNoCookie {
			cookie = &http.Cookie{
				Name:     "logged-in",
				Value:    "0",
				HttpOnly: true,
			}
		}
	*/
	cookie, err := req.Cookie("session-id")
	if err == http.ErrNoCookie {
		http.Redirect(w, req, "/login", 303)
		return
	}

	var loggedin bool
	var us *user
	for _, u := range users {
		if cookie.Value == u.Session {
			loggedin = true
			us = u
			break
		}
	}
	if !loggedin {
		http.Redirect(w, req, "/login", 303)
		return
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

	err = tpl.ExecuteTemplate(w, "index.gohtml", us) //files[:len(files)-1])
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
	http.ServeFile(w, req, "temp.zip")
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

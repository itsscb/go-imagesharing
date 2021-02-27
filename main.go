package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"text/template"
	"time"

	uuid "github.com/satori/go.uuid"
)

var tpl *template.Template
var images []string
var jusers []user

var users = make(map[string]*user)
var files []os.FileInfo

type session struct {
	ID           string
	lastActivity time.Time
}

type user struct {
	Username string
	Password string
	Session  session
	Files    []os.FileInfo
}

func main() {
	rmfolders, err := ioutil.ReadDir("public/")
	if err != nil {
		fmt.Println(err)
	}
	for _, f := range rmfolders {
		os.RemoveAll("public/" + f.Name())
	}

	newfolders, err := ioutil.ReadDir("private/")
	if err != nil {
		fmt.Println(err)
	}
	for _, f := range newfolders {
		if f.IsDir() && f.Name() != "img" {
			cpdir("private/"+f.Name(), "public/"+f.Name())
		} else if !f.IsDir() && f.Name() != "img" {
			cpfile("private/"+f.Name(), "public/"+f.Name())
		}
	}

	files, err = ioutil.ReadDir("private/img")
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
	for _, u := range jusers {
		users[u.Username] = &user{
			Username: u.Username,
			Password: u.Password,
			Session: session{
				ID:           "0",
				lastActivity: time.Now().Add(-1400),
			},
			Files: nil,
		}
	}

	go cleanSessions()

	fsp := http.FileServer(http.Dir("./public/"))
	http.Handle("/public/", http.StripPrefix("/public/", fsp))
	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", login)
	//http.HandleFunc("/download", download)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":8080", nil)
}

func init() {
	tpl = template.Must(template.ParseGlob("templates/*.gohtml"))
}

func index(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("session-id")
	if err == http.ErrNoCookie {
		http.Redirect(w, req, "/login", 303)
		return
	}

	var loggedin bool
	var us *user
	for _, u := range users {
		if cookie.Value == u.Session.ID {
			loggedin = true
			u.Session.lastActivity = time.Now()
			startSession(u)
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
		for _, y := range x {
			images = append(images, y)
		}
	}

	if len(images) >= 1 {
		output := "temp_" + time.Now().String() + ".zip"
		if err := zipFiles(output, images, us.Session.ID); err != nil {
			fmt.Println(err)
		}
		images = nil
		f, err := os.Open(output)
		if err != nil {
			fmt.Println(err)
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			fmt.Println(err)
		}
		w.Header().Set("Content-Disposition", "attachment; filename=pictures.zip")
		http.ServeContent(w, req, fi.Name(), fi.ModTime(), f)
		os.RemoveAll(output)
		//http.Redirect(w, req, "/download", 303)
	}

	err = tpl.ExecuteTemplate(w, "index.gohtml", us)
	if err != nil {
		http.Error(w, err.Error(), 500)
		fmt.Println(err)
	}
}

func login(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("session-id")
	nid, _ := uuid.NewV4()
	if err == http.ErrNoCookie {
		cookie = &http.Cookie{
			Name:   "session-id",
			Value:  nid.String(),
			MaxAge: 1200,
			// Secure: true,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
	}

	if req.Method == "POST" {
		password := req.FormValue("password")
		username := req.FormValue("username")
		for _, u := range users {
			if password == u.Password && username == u.Username {
				cookie = &http.Cookie{
					Name:   "session-id",
					Value:  nid.String(),
					MaxAge: 1200,
					// Secure: true,
					HttpOnly: true,
				}
				http.SetCookie(w, cookie)
				users[u.Username].Session.ID = cookie.Value
				startSession(u)
			}

		}
	}
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
		if cookie.Value == u.Session.ID {
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

/*
func download(w http.ResponseWriter, req *http.Request) {
	output := "temp_" + time.Now().String() + ".zip"
	if err := zipFiles(output, images); err != nil {
		fmt.Println(err)
	}
	images = nil
	f, err := os.Open(output)
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		fmt.Println(err)
	}
	w.Header().Set("Content-Disposition", "attachment; filename=pictures.zip")
	http.ServeContent(w, req, fi.Name(), fi.ModTime(), f)
	os.RemoveAll(output)
	return
}
*/
func startSession(u *user) {
	path := "public/" + u.Session.ID + "/"
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		_ = os.Mkdir(path, 0755)
	} else {
		return
	}
	for _, f := range files {
		cpfile("private/img/"+f.Name(), path+f.Name())
		if f.Name() != "index.html" {
			u.Files = append(u.Files, f)
		}
		file, err := os.OpenFile("public/"+u.Session.ID+"/"+f.Name(), os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
		}
		defer file.Close()
		if _, err := file.WriteString(time.Now().Format("2006-01-02 15:04") + " " + u.Username); err != nil {
			log.Fatal(err)
		}
	}
}

func cleanSessions() {
	for true {
		for _, u := range users {
			if time.Now().Sub(u.Session.lastActivity) > (time.Second * 1200) {
				os.RemoveAll("public/" + u.Session.ID)
				users[u.Username].Session.ID = "0"
			}
		}
		time.Sleep(1800)
	}
}

// ZIP-Functions
func zipFiles(filename string, files []string, s string) error {

	newZipFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()
	err = os.Chdir("public/" + s)
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

// Copy-Functions
func cpfile(src, dst string) error {
	var err error
	var srcfd *os.File
	var dstfd *os.File
	var srcinfo os.FileInfo

	if srcfd, err = os.Open(src); err != nil {
		return err
	}
	defer srcfd.Close()

	if dstfd, err = os.Create(dst); err != nil {
		return err
	}
	defer dstfd.Close()

	if _, err = io.Copy(dstfd, srcfd); err != nil {
		return err
	}
	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}
	return os.Chmod(dst, srcinfo.Mode())
}

func cpdir(src string, dst string) error {
	var err error
	var fds []os.FileInfo
	var srcinfo os.FileInfo

	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}

	if err = os.MkdirAll(dst, srcinfo.Mode()); err != nil {
		return err
	}

	if fds, err = ioutil.ReadDir(src); err != nil {
		return err
	}
	for _, fd := range fds {
		srcfp := path.Join(src, fd.Name())
		dstfp := path.Join(dst, fd.Name())

		if fd.IsDir() {
			if err = cpdir(srcfp, dstfp); err != nil {
				fmt.Println(err)
			}
		} else {
			if err = cpfile(srcfp, dstfp); err != nil {
				fmt.Println(err)
			}
		}
	}
	return nil
}

// eof

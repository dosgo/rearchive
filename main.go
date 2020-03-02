package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/nwaples/rardecode"
	"github.com/pkg/profile"
	"io"
	"io/ioutil"
	"log"
	"math"
	"os"
	"strconv"
	"sync"
	"time"
)

var (
	aPath      string
	tNum       int
	pwdDict    string
	lock       sync.Mutex
	speedTotal map[int64]int
)

func init() {
	flag.StringVar(&aPath, "aPath", "test.rar", "this is archive Path")                  //
	flag.IntVar(&tNum, "tNum", 1, "this is help threads number.")                        //
	flag.StringVar(&pwdDict, "pwdDict", "000webhost.txt", "this is help password dict.") //
	speedTotal = make(map[int64]int)

}

func main() {
	defer profile.Start().Stop()
	log.Printf("rearchive V0.1\r\n")
	flag.Parse()


	if aPath == "" || pwdDict == "" {
		flag.PrintDefaults()
		return
	}
	//read password dict
	lineNum, err := getLineNum(pwdDict)
	if err != nil {
		return
	}
	//tNum
	if lineNum < tNum {
		tNum = 1
	}
	pageSize := int(math.Floor(float64(lineNum / tNum)))
	for i := 0; i < tNum; i++ {
		//
		if i == tNum-1 {
			go startRePwd(i*pageSize, i*pageSize+pageSize+tNum)
		} else {
			go startRePwd(i*pageSize, i*pageSize+pageSize)
		}
	}
	fmt.Printf("speed:")

	for {
		displayTotal()
		time.Sleep(1 * time.Second)
	}
}

/*start re password*/
func startRePwd(startLine int, endLine int) {
	fi, err := os.Open(pwdDict)
	if err != nil {
		return
	}
	defer fi.Close()
	br := bufio.NewReader(fi)
	zb,err:=ioutil.ReadFile(aPath)
	zr:=bytes.NewBuffer(zb)
	var i = 0
	for {
		line, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		i++
		//线程范围
		if i >= startLine && i <= endLine {
			    zr.Reset()
			    zr.Write(zb)
				ok, err := checkPwd(zr,string(line))
				if err == nil && ok {
					log.Printf("password is %s\r\n", string(line))
					os.Exit(0)
				}

			//total +1;
			incrTotal()
		}
	}
	return
}

func incrTotal() {
	lock.Lock()
	tm := time.Now().Unix()
	if _, ok := speedTotal[tm]; ok {
		speedTotal[time.Now().Unix()] = speedTotal[time.Now().Unix()] + 1
	} else {
		speedTotal[time.Now().Unix()] = 1
	}
	lock.Unlock()
}

func displayTotal() {
	lock.Lock()
	tm := time.Now().Unix() - 1
	if num, ok := speedTotal[tm]; ok {
		out := strconv.Itoa(num)
		fmt.Printf(out)
		for i := 0; i < len(out); i++ {
			fmt.Printf("\b")
		}
		delete(speedTotal, tm) //删除key值为2的map
	}



	lock.Unlock()
}

/*获取行数*/
func getLineNum(fname string) (int, error) {
	fi, err := os.Open(fname)
	if err != nil {
		return 0, err
	}
	defer fi.Close()
	br := bufio.NewReader(fi)
	var i = 0
	for {
		_, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		i++
	}
	return i, nil
}
/*sian*/
func checkPwd(zr io.Reader,password string) (bool, error) {
	r, err := rardecode.NewReader(zr,password);
	if err != nil {
		return false, err
	}
	_, err = r.Next()
	if err != nil  {
		return false, nil
	}
	_, err = ioutil.ReadAll(r)
	if(err!=nil){
		return false,nil;
	}
	return true, nil
}



/*
check password
NewReader only supports single volume archives.
*/
func checkPwdNew( password string) (bool, error) {
	//	log.Printf("password:%s len:%d\r\n", password, len(password)
	r, err := rardecode.OpenReader(aPath, password)
	if err != nil {
		return false, err
	}
	_, err = r.Next()
	if err != nil  {
		return false, nil
	}
	_, err = ioutil.ReadAll(r)
	if(err!=nil){
		return false,nil;
	}
	return true, nil
}


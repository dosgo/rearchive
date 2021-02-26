package rar

import (
	"bufio"
	"fmt"
	"github.com/nwaples/rardecode"
	"github.com/spf13/afero"
	"io"
	"io/ioutil"
	"errors"
	"log"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var (
	speedTotal uint64
	lastTotal  uint64
	startTime  int64
	memFs afero.Fs
)

func init() {
	speedTotal=0;
	lastTotal=0;
	startTime=0;
	memFs = afero.NewMemMapFs()
}

/*sian*/
func checkPwd(memFs afero.Fs,aPath string,password string) (bool, error) {
	zr,err:=memFs.Open(aPath)
	if(err!=nil){
		return false,errors.New("open rar error")
	}
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
check rar
NewReader only supports single volume archives.
*/
func checkPwdNew(aPath string, password string) (bool, error) {
	//	log.Printf("rar:%s len:%d\r\n", rar, len(rar)
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

func consumerPwd(wg *sync.WaitGroup,aPath string, passwords <-chan string) {
	for password := range passwords {
		//fmt.Printf("rar:%s\r\n",rar)
		ok,err:=checkPwd(memFs,aPath,password);
		if ok &&err==nil {
			fmt.Printf("\r\nrar is %s runTime:%ds\r\n", password, time.Now().Unix()-startTime)
			os.Exit(0)
		}
	}
	wg.Done()
}



func displayTotal() {
	v := atomic.LoadUint64(&speedTotal)
	num:=v-lastTotal;
	lastTotal=v;
	out := strconv.Itoa(int(num))
	fmt.Printf("%d",num)
	for i := 0; i < len(out); i++ {
		fmt.Printf("\b")
	}
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



/**/
func StatRePwd(aPath string,pwdDict string,tNum int){
	//mem file
	zb,err:=ioutil.ReadFile(aPath)
	if err != nil {
		log.Printf("read rar file error! err:%v\r\n",err)
		return
	}
	afero.WriteFile(memFs, aPath,zb, 0644)
	if err != nil {
		log.Printf("copy rar file to memfs error! err:%v\r\n",err)
		return
	}

	//read rar dict
	lineNum, err := getLineNum(pwdDict)
	if err != nil {
		return
	}
	//tNum
	if lineNum < tNum {
		tNum = 1
	}

	startTime=time.Now().Unix();
	fmt.Printf("speed:")
	go func() {
		for {
			displayTotal()
			time.Sleep(1 * time.Second)
		}
	}()

	fi, err := os.Open(pwdDict)
	if err != nil {
		return
	}
	defer fi.Close()
	br := bufio.NewReader(fi)
	var wgc sync.WaitGroup
	passWords := make(chan string, 20)
	for i := 0; i < tNum; i++ {
		go consumerPwd(&wgc,aPath, passWords)
		wgc.Add(1)
	}
	for {
		line, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		passWords <- string(line)
		atomic.AddUint64(&speedTotal,1)
	}
	wgc.Wait()
}

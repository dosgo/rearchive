package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/spf13/afero"
	"io"
	"io/ioutil"
	"log"
	"os"
	"rearchive/rar"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var (
	aPath      string
	tNum       int
	pwdDict    string
	speedTotal uint64
	lastTotal  uint64
	startTime  int64
	memFs afero.Fs
)

func init() {
	flag.StringVar(&aPath, "aPath", "test.rar", "this is archive Path")                  //
	flag.IntVar(&tNum, "tNum", 10, "this is help threads number.")                        //
	flag.StringVar(&pwdDict, "pwdDict", "000webhost.txt", "this is help rar dict.") //
	speedTotal=0;
	lastTotal=0;
	startTime=0;
	memFs = afero.NewMemMapFs()
}

func main() {
	//defer profile.Start().Stop()
	log.Printf("rearchive V0.2\r\n")
	flag.Parse()
	if aPath == "" || pwdDict == "" {
		flag.PrintDefaults()
		return
	}

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
	go startRePwd();
	for {
		displayTotal()
		time.Sleep(1 * time.Second)
	}
}




/*start re rar*/
func startRePwd() {
	fi, err := os.Open(pwdDict)
	if err != nil {
		return
	}
	defer fi.Close()
	br := bufio.NewReader(fi)
	var wgc sync.WaitGroup
	passWords := make(chan string, 20)
	for i := 0; i < tNum; i++ {
		go consumerPwd(&wgc, passWords)
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
	return
}


func consumerPwd(wg *sync.WaitGroup, passwords <-chan string) {
	for password := range passwords {
		//fmt.Printf("rar:%s\r\n",rar)
		ok,err:=rar.CheckPwd(memFs,aPath,password);
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


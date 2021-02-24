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
	"os/exec"
	"path/filepath"
	"rearchive/hash"
	"rearchive/rar"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	aPath      string
	tNum       int
	hashCat    bool;
	pwdDict    string
	pwdFormat  string;
	speedTotal uint64
	lastTotal  uint64
	startTime  int64
	memFs afero.Fs
)

func init() {
	flag.StringVar(&aPath, "aPath", "test.rar", "this is archive Path.")                  //
	flag.IntVar(&tNum, "tNum", 10, "this is help threads number.")                        //
	flag.StringVar(&pwdDict, "pwdDict", "", "this is help rar dict.") //
	flag.StringVar(&pwdFormat, "pwdFormat", "?a?a?a?a?a?a?a?a?a?a", "this is hastcat pwd Format.") //
	flag.BoolVar(&hashCat, "hashCat", true, "use hashCat.") //
	speedTotal=0;
	lastTotal=0;
	startTime=0;
	memFs = afero.NewMemMapFs()
}

func main() {
	//defer profile.Start().Stop()
	log.Printf("rearchive V0.2-20210224\r\n")
	flag.Parse()
	if aPath == ""  {
		flag.PrintDefaults()
		return
	}

	//
	if hashCat {
		bin:="hashcat.exe"
		if runtime.GOOS!="windows"{
			bin="hashcat"
		}
		_,err:=exec.LookPath(bin);
		if err!=nil {
			fmt.Printf("Cannot find hashcat, please confirm that it is installed and added to the environment variable $path\r\n")
			return ;
		}
		code := hash.Rar2HashFile(aPath)
		if code!=0{
			fmt.Printf("get hash error\r\n");
		}else{
			var m="";
			var a="3";
			var hashStr="";
			var pass="?d?d?d?d?d?d";

			if len(pwdDict)>0 {
				a="0";
				if !filepath.IsAbs(pwdDict) {
					pass,_=filepath.Abs(pwdDict)
				}else {
					pass = pwdDict;
				}
			}else{
				pass=pwdFormat;
			}


			sPos:= strings.Index(hash.Out,":")
			if sPos==-1 {
				fmt.Printf("get hash error\r\n");
				return
			}

			_hashStr:=hash.Out[sPos+1:];
			//rar5
			if strings.HasPrefix(strings.ToLower(_hashStr), "$rar5") {
				m="13000"
				hashStr= strings.Replace(_hashStr, "\n", "", -1)
			}
			//rar3
			if  strings.HasPrefix(strings.ToLower(_hashStr), "$rar3"){
				//rar3-hp
				if strings.HasPrefix(strings.ToLower(_hashStr), "$rar3$*0*") {
					ePos := strings.Index(_hashStr, ":");
					//rar3-hp
					hashStr= strings.Replace(_hashStr[:ePos], "\n", "", -1)
					m="12500"
				}else {
					ePos := strings.Index(_hashStr, "::");
					if len(_hashStr[:ePos]) > 100 {
						m = "23800"
					} else {
						m = "23700"
					}
					//rar3-p
					hashStr = strings.Replace(_hashStr[:ePos-2], "\n", "", -1)
				}
			}
			password,err:=hashCatRun(m,a,hashStr,pass)
			if err!=nil{
				fmt.Printf("%s",err.Error())
			}else{
				fmt.Printf("password:%s\r\n",password)
			}
		}
	}else{
		rePwd();
	}
}

/*exec */
func hashCatRun(m string,a string,hashStr string,pass string)(string,error){
	fmt.Printf("\r\n start hashcat ...\r\n");
	bin:="hashcat.exe"
	if runtime.GOOS!="windows"{
		bin="hashcat"
	}
	var cmd *exec.Cmd
	if(a=="3"){
		incrementMax:=strconv.Itoa(len(pass)/2);

		//--increment --increment-min 1 --increment-max 8
		cmd= exec.Command(bin, "-m",m,"-a",a,hashStr,"--increment","--increment-min","1","--increment-max",incrementMax,pass)

	}else{
		//--increment --increment-min 1 --increment-max 8
		cmd= exec.Command(bin, "-m",m,"-a",a,hashStr,pass)
	}


	fmt.Printf("cmd.args:%v\r\n",cmd.Args)
	cmd.Dir=filepath.Dir(cmd.Path);
	stdoutIn, _ := cmd.StdoutPipe()
	stderrIn, _ := cmd.StderrPipe()
	cmd.Start()
	go func() {
		io.Copy(os.Stdout, stdoutIn)
	}()
	go func() {
		io.Copy(os.Stderr, stderrIn)
	}()

	err:= cmd.Wait()
	outStr,_:=os.ReadFile(filepath.ToSlash(cmd.Dir)+"/hashcat.potfile");
	outs:=strings.Split(string(outStr),"\n");

	for _, _v:= range outs {
		_pos:=strings.Index(_v,hashStr)
		if _pos!=-1 {
			if len(_v)>len(hashStr)+2 {
				return _v[_pos+len(hashStr)+1:],nil;
			}
			return "",err;
		}
	}
	return "",err;
}

/**/
func rePwd(){
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

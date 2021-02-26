package rar

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"rearchive/hash"
	"runtime"
	"strconv"
	"strings"
)


func StartHashCat(aPath string,pwdDict string, pwdFormat string){
	bin:=getHashCatExe();
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
		var pass="?a?a?a?a?a?a";

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
}


func getHashCatExe() string{
	bin:="hashcat.exe"
	if runtime.GOOS!="windows"{
		bin="hashcat"
	}
	return bin
}


/*exec */
func hashCatRun(m string,a string,hashStr string,pass string)(string,error){
	fmt.Printf("\r\n start hashcat ...\r\n");
	bin:=getHashCatExe();
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
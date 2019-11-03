package main
import (
	"bufio"
	"flag"
	"github.com/mholt/archiver"
	"github.com/nwaples/rardecode"
	"io/ioutil"
	"strconv"
	"sync"
	"time"
	"fmt"
	"io"
	"math"
	"os"
)
import "log"
var(
	aPath  string
	tNum   int
	pwdDict string
	lock sync.Mutex
	speedTotal map[int64]int
)
func init(){
	flag.StringVar(&aPath, "aPath", "test.rar", "this is archive Path") //
	flag.IntVar(&tNum, "tNum", 1, "this is help threads number.") //
	flag.StringVar(&pwdDict, "pwdDict", "000webhost.txt", "this is help password dict.") //
	speedTotal = make(map[int64]int)

}

func main(){
	log.Printf("rearchive V0.1\r\n");
	flag.Parse()

	if(aPath==""||pwdDict=="") {
		flag.PrintDefaults()
		return;
	}
	checkPwd(aPath,"0010011password");

	//read password dict
	lineNum,err:=getLineNum(pwdDict);
	if(err!=nil){
		return;
	}
	//tNum
	if(lineNum<tNum){
		tNum=1;
	}
	pageSize:=int(math.Floor(float64(lineNum/tNum)));
	for i:=0;i<tNum;i++{
		//
		if(i==tNum-1){
			go startRePwd(i*pageSize, i*pageSize+pageSize+tNum);
		}else {
			go startRePwd(i*pageSize, i*pageSize+pageSize);
		}
	}
	fmt.Printf("speed:");

	for{
		displayTotal();
		time.Sleep(1*time.Second);
	}
}


/*start re password*/
func startRePwd(startLine int,endLine int){
	fi, err := os.Open(pwdDict)
	if err != nil {
		return ;
	}
	defer fi.Close()
	br := bufio.NewReader(fi)
	var  i=0;
	for {
		line, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		i++;
		//线程范围
		if(i>=startLine&&i<=endLine){
			ok,err:=checkPwd(aPath,string(line));
			if(err==nil&& ok){
				log.Printf("password is %s\r\n",string(line));
				os.Exit(0);
			}
			//total +1;
			incrTotal();
		}
	}
	return ;
}


func incrTotal(){
	lock.Lock()
	tm:=time.Now().Unix();
	if _, ok := speedTotal[tm]; ok {
		speedTotal[time.Now().Unix()]=speedTotal[time.Now().Unix()]+1;
	}else {
		speedTotal[time.Now().Unix()] = 1;
	}
	lock.Unlock()
}

func displayTotal(){
	lock.Lock()
	tm:=time.Now().Unix()-1;
	if num, ok := speedTotal[tm]; ok {
		out:=strconv.Itoa(num);
		fmt.Printf(out);
		for i:=0;i<len(out);i++{
			fmt.Printf("\b");
		}
		delete(speedTotal, tm) //删除key值为2的map
	}
	lock.Unlock()
}

/*获取行数*/
func getLineNum(fname string) (int,error){
	fi, err := os.Open(fname)
	if err != nil {
		return 0,err;
	}
	defer fi.Close()
	br := bufio.NewReader(fi)
	var  i=0;
	for {
		_, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		i++;
	}
	return i,nil;
}




/*check password*/
func checkPwd(archivePath string,password string)(bool,error){
	log.Printf("password:%s len:%d\r\n",password,len(password));
	r,err:= rardecode.OpenReader(archivePath,password)
	defer  r.Close();
	if(err!=nil){
		return false,err;
	}
	_,err=r.Next();
	if(err!=nil){
		return false,nil;
	}
	_, err = ioutil.ReadAll(r)
	if(err!=nil){
		return false,nil;
	}
	return true,nil;

}

func checkPwdv1(archivePath string,password string)(bool,error){
	r := archiver.NewRar()
	r.Password=password;
	err:=r.Walk(archivePath, func(f archiver.File) error {
		_, ok := f.Header.(*rardecode.FileHeader)
		if !ok {
			return fmt.Errorf("expected header")
		}
		_, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}
		return nil
	})
	if(err!=nil){
		return false,nil;
	}
	return true,nil;
}
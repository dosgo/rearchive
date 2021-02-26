package main

import (
	"flag"
	"log"
	"rearchive/rar"
)

var (
	aPath      string
	tNum       int
	hashCat    bool;
	pwdDict    string
	pwdFormat  string;
)

func init() {
	flag.StringVar(&aPath, "aPath", "test.rar", "this is archive Path.")                  //
	flag.IntVar(&tNum, "tNum", 10, "this is help threads number.")                        //
	flag.StringVar(&pwdDict, "pwdDict", "", "this is help rar dict.") //
	flag.StringVar(&pwdFormat, "pwdFormat", "?a?a?a?a?a?a?a?a?a?a", "this is hastcat pwd Format.") //
	flag.BoolVar(&hashCat, "hashCat", true, "use hashCat.") //
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
		rar.StartHashCat(aPath,pwdDict,pwdFormat);
	}else{
		if pwdDict=="" {
			flag.PrintDefaults()
			return
		}
		rar.StatRePwd(aPath,pwdDict,tNum);
	}
}








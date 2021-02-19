package rar

import (
	"github.com/nwaples/rardecode"
	"github.com/spf13/afero"
	"io/ioutil"
	"errors"
)

/*sian*/
func CheckPwd(memFs afero.Fs,aPath string,password string) (bool, error) {
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
func CheckPwdNew(aPath string, password string) (bool, error) {
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

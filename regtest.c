#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[])
{
	unsigned long r, disp, serial, type, datasize;
	unsigned char data[32];
	HKEY key;
	
	r = RegCreateKeyEx(
		HKEY_LOCAL_MACHINE,
		"SOFTWARE\\ARMSerial\\NM",
		0,
		"", // address of class string
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		0,
		&key,
		&disp);
	if(r == ERROR_SUCCESS) MessageBox(0,"OK","OK",MB_OK);
	else 
	{
		MessageBox(0,"FAIL","FAIL",MB_OK);
		return 0;
	}

	r = RegQueryValueEx(key,"lastserial",0,&type,data,&datasize);
	if(r) return 0;

	serial = *(unsigned long*)data;
	serial++;
	r = RegSetValueEx(key,"lastserial",0,REG_DWORD,(unsigned char*)&serial,4);

	RegCloseKey(key);

	return 0;
}
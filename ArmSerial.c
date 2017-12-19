/**************************************************************
Serial Number/Datestamp Generation
Version 1.02

1.00 - Modifikovano tako da zadnji generisani serijski broj cuva u 
registry bazi. Serijski brojevi u bezi zavise od prefixa i 
nezavisni su za svaki prefix.

1.01 - Dodat -n parametar na komandnoj liniji za generisanje HEX fajla
bez inkrementovanja brojaca u registry bazi

1.02 - Dodat -p parametar na komandnoj liniji za printanje serial 
stringa na stdio

Serijski broj se sastoji od rednog broja, timestamp stringa i proizvoljnog prefixa.
- Prefix moze biti bilo koji string bez praznina do 5 karaktera duzine. 
  Ako je prefix duzi odsjeca se na 5 karaktera.
- Time stamp sadrzi 14 ASCII cifara i ima format YYYYMMDDHHMMSS.
- Redni broj se sastoji od 10 decimalnih cifara i moze biti u opsegu od 0000000001 do 4294967295. 

  Sve zajedno: PPPPP-YYYYMMDDHHmmSS-RRRRRRRRRR

**************************************************************/

#define VERSION_STRING "1.02"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "hexfile.h"

// location in flash memory to store serial number at
unsigned long address;

// flag za inkrementovanje serijskog broja u registry bazi
int increment = 1; // po defaultu se inkrementuje

// putanja u registry bazi
#define REG_PATH "SOFTWARE\\ARMSerial"

// ime varijable u registry bazi
#define REG_VALUE "lastserial"

// array to hold serial number/datestamp
char serialnumber[32];

// prefix serijskog broja
char serialprefix[8];

// function to generate the actual serial number and put it into
// an intel hex record ready for programming
// outputfile = handle of file to write hex record
int generate(FILE *outputfile)
{
	char hexrecord[100];
	char regpath[100];
	unsigned long now, r, serial;
	HKEY key;
	struct tm* timedate;

	// formira se registry path
	strcpy(regpath,REG_PATH);
	strcat(regpath,"\\");
	strcat(regpath,serialprefix);

	r = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		regpath,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		&key);
	if(r) // nije uspjelo -- valjda ne postoji taj kljuc u ragistry bazi
	{
		// kraira se kljuc u bazi
		unsigned long disp;

		r = RegCreateKeyEx(
			HKEY_LOCAL_MACHINE,
			regpath,
			0,
			"", // address of class string
			REG_OPTION_NON_VOLATILE,
			KEY_ALL_ACCESS,
			0,
			&key,
			&disp);
		if(r) // ako ni ovo ne uspije odustajem
		{
			return -1;
		}

		serial = 1;
		r = RegSetValueEx(
			key,
			REG_VALUE,
			0,
			REG_DWORD,
			(unsigned char*)&serial,
			4);

		// key vise nije potreban
		RegCloseKey(key);

		if(r) // ako nije uspjelo ...
		{
			return -1;
		}
	}
	else // path postoji -- treba samo procitati vrijednost
	{
		unsigned long datasize, type;

		datasize = 4;

		r = RegQueryValueEx(
			key,
			REG_VALUE,
			0,
			&type,
			(unsigned char*)&serial,
			&datasize);
		if(r || (datasize != 4) || (type != REG_DWORD))
		{
			RegCloseKey(key);
			return -1;
		}
		// zadnji serijski broj je u serial
		if(increment) serial++; // za 1 veci

		// upisuje se nova vrijednost u registry
		r = RegSetValueEx(
			key,
			REG_VALUE,
			0,
			REG_DWORD,
			(unsigned char*)&serial,
			4);

		RegCloseKey(key);

		if(r) // ako nije uspjelo ...
		{
			return -1;
		}
	}

	// get the current time
	time((time_t *)&now);
	timedate = localtime(&now);
	
	// store current time in serial number array
	sprintf(
		serialnumber,
		"%s-%04d%02d%02d%02d%02d%02d-%010u",
		serialprefix,
		1900 + timedate->tm_year,
		1 + timedate->tm_mon,
		timedate->tm_mday,
		timedate->tm_hour,
		timedate->tm_min,
		timedate->tm_sec,
		serial);
	
	// create a hex record holding the serial number  
	hexfile_generate_record(
		address,
		strlen(serialnumber) + 1, 
		serialnumber, 
		hexrecord);

	// output the hex record
	fprintf(outputfile, "%s\n", hexrecord);

	return 0; // OK
}
 

// function to remove carriage returns and newlines from the
// end of a line
void strip_newline(char *text)
{
	char *ptr = text;
	while (*ptr)
	{
		if (*ptr == '\n' || *ptr == '\r') *ptr = '\0';
		ptr++;
	}
}

// main function
int main(int argc, char **argv)
{
	FILE *commandfile;
	FILE *datafile;
	FILE *userfile;
	char datafilepath[2000];
	char userfilepath[2000];
	char serialaddress[16];
	int ret_code = 1; // OK
	int print = 0;

	// if we didn't receive two arguments then we can't do
	// anything
	if(argc < 2 || argc > 5)
	{
		fprintf(stderr,"ArmSerial, version %s, build date: %s\n",VERSION_STRING,__DATE__);
		fprintf(stderr,"Usage: ArmSerial path_to_command_file [option[ option]]\n");
		fprintf(stderr,"Oprions: -i     invert return code (return 0 if OK, 1 if FAIL)\n");
		fprintf(stderr,"         -n     don't increment sequence number in registry\n");
		fprintf(stderr,"         -p     print user-file to stdout\n");
		fprintf(stderr,"\n");
		fprintf(stderr,"Command file contain 4 lines with 1 parameter per line:\n");
		fprintf(stderr,"absolute path to hex file\n");
		fprintf(stderr,"absolute path to user file\n");
		fprintf(stderr,"serial string prefix (up to 5 chars)\n");
		fprintf(stderr,"serial string address in HEX file (in HEX notation)\n");
		return ! ret_code; // FAIL
	}
	while(argc > 2)
	{
		if(argv[argc - 1][0] == '-')
		{
			if(argv[argc - 1][1] == 'i') ret_code = 0; // invertovano
			else if(argv[argc - 1][1] == 'n') increment = 0; // nema inkrementovanja
			else if(argv[argc - 1][1] == 'p') print = 1; // print na stdout
			// nepoznata opcija se ignorise
		}
		argc--;
	}

	// try to open the command file passed in the first argument
	commandfile = fopen(argv[1], "r");
	if (!commandfile) return ! ret_code;

	// try to read in the path to the file to create with hex
	// records
	if(fgets(datafilepath, 2000, commandfile) == NULL)
	{
		fclose(commandfile);
		return ! ret_code;
	}

	// try to read in the path to the user output file to
	// create
	if(fgets(userfilepath, 2000, commandfile) == NULL)
	{
		fclose(commandfile);
		return ! ret_code;
	}


	// try to read in the serial prefix
	if(fgets(serialprefix, 8, commandfile) == NULL)
	{
		fclose(commandfile);
		return ! ret_code;
	}
	serialprefix[5] = 0; // ogranicava se prefix na 5 karaktera

	// try to read in the serial address
	if(fgets(serialaddress, 16, commandfile) == NULL)
	{
		fclose(commandfile);
		return ! ret_code;
	}

	// we are done with the command file
	fclose(commandfile);

	// get rid of junk we don't need
	strip_newline(datafilepath);
	strip_newline(userfilepath);
	strip_newline(serialprefix);
	strip_newline(serialaddress);

	address = 0;
	sscanf(serialaddress,"0x%x",&address);
	if(address == 0) return ! ret_code;

	// create file for hex records and generate records
	datafile = fopen(datafilepath, "wb");
	if(!datafile) return ! ret_code;

	if(generate(datafile) == -1) return ! ret_code; // FAIL

	fclose(datafile);

	// create file for user output and put something in there
	userfile = fopen(userfilepath, "w");
	if(!userfile) return ! ret_code;

	// generate some feedback for the user
	// in this case we tell the user what the serial number is generated
	// so it can be noted and maybe put on a sticker somewhere
	fprintf(userfile, "%s", serialnumber);
	fclose(userfile);

	// if requested, print serial to stdio
	if(print) printf("%s\n",serialnumber);

	// done
	return ret_code;
}

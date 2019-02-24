/**************************************************************
1.2 - Changed last_sequence_file file format from binary to ASCII.
      Old binary files can still be read.

1.1 - promjenjeno ime ovog fajla iz ArmSerial.c u hexserial.c
    - promjenjeno ponasanje: ako hex i txt fajlovi nisu navedeni program nastavlja dalje ali se ne zali
    - promjenjeno ponasanja: ako prefix nije naveden format postaje YYYYMMDDHHmmss-RRRRRR
    - izbacen -n flag za ne-inkrementovanje i vracena -i opcija za inkrementovanje
    - nema default radnji, sve se mora specificirati
    - operacije: inkrement, force, update. Kombinacije su:
    000: re-make last serial
    001: not permitted
    010: force sequence number and make serial
    011: force sequence number, make serial and update last-sequence file
    100: increment last sequence number and make serial
    101: increment last sequence number, make serial and update last-sequence file
    110: not permitted
    111: not permitted
    - svi tekstovi koji se ispisuju prevedeni na engleski


1.06 - Svi globalni parametri prebaceni u strukturu hex_cfg

1.05 - Dodata je -F opcija da se umjesto u registry podaci cuvaju u fajlu.
To je bitno zbog sigurnosnih razloga kada se podaci trebaju cuvati zajedno sa HEX kodom.

1.04 - Modifikovan je format serijskog broja tako sto je povecana duzina
prefixa sa 5 na 9 karaktera a smanjena duzina serijskog broja sa 10 na 6 cifara.
U komandnom fajlu se # ili ; na pocetku linije koriste da oznace komentar

Serijski broj se sastoji od rednog broja, timestamp stringa i proizvoljnog
prefixa.
- Prefix moze biti bilo koji string bez praznina do 9 karaktera duzine. Ako je
prefix duzi odsjeca se na 9 karaktera.
- Time stamp sadrzi 14 ASCII cifara i ima format YYYYMMDDHHMMSS.
- Redni broj se sastoji od 6 decimalnih cifara i moze biti u opsegu od
000001 do 999999.
Sve zajedno: PPPPPPPPP-YYYYMMDDHHmmSS-RRRRRR

1.03 - Dodat -f parametar na komandnoj liniji da se forsira serijski broj
Dodat -u parametar na komandnoj liniji da se serijski broj dat
sa -f spremi u registry bazu. Koristi se samo zajedno sa -f

Serijski broj se sastoji od rednog broja, timestamp stringa i proizvoljnog
prefixa.
- Prefix moze biti bilo koji string bez praznina do 5 karaktera duzine. Ako je
prefix duzi odsjeca se na 5 karaktera.
- Time stamp sadrzi 14 ASCII cifara i ima format YYYYMMDDHHMMSS.
- Redni broj se sastoji od 10 decimalnih cifara i moze biti u opsegu od
0000000001 do 4294967295.
Sve zajedno: PPPPP-YYYYMMDDHHmmSS-RRRRRRRRRR

1.02 - Dodat -p parametar na komandnoj liniji za printanje serial
stringa na stdio

1.01 - Dodat -n parametar na komandnoj liniji za generisanje HEX fajla
bez inkrementovanja brojaca u registry bazi

1.00 - Modifikovano tako da zadnji generisani serijski broj cuva u
registry bazi. Serijski brojevi u bezi zavise od prefixa i
nezavisni su za svaki prefix.

**************************************************************/

#define VERSION_STRING "1.2"

// include needed header files
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "hexfile.h"


#ifndef MAX_PATH
#define MAX_PATH 2048
#endif

#define MAX_SERIAL_SIZE 64


typedef struct hex_cfg
{
    // location in flash memory to store serial number at
    unsigned int address;

    // action flags
    int increment, update, force;

    // forced sequence number
    unsigned int sequence;

    // the name of last sequence file
    char* last_serial_file;

    char* datafilepath;
	char* userfilepath;

    // array to hold serial number/timestamp
    char serialnumber[MAX_SERIAL_SIZE];

    // serial number prefix
    char* serialprefix;
} hex_cfg;


void hex_cfg_init(hex_cfg* cfg)
{
    memset(cfg, 0, sizeof(hex_cfg));
}


// returns sequence number >= 0 from binary or ascii file
// returns 0 if there is no file of file is empty
// returns negative error code on error
int get_sequence_number(char* last_serial_file)
{
    FILE* fp;
    int value, size, err;
    struct stat stat_buf;
    char buff[32];

    if(!last_serial_file) return -1;

    err = stat(last_serial_file, &stat_buf);
    if(err)
    {
        // stat failed

        // if there is no file return 0 as sequence number
        if(errno == ENOENT) return 0;
        // it's some other error, return error code
        perror("Error in get_sequence_number()");
        return -2;
    }

    // if file size is 0 return 0 as sequence number
    if(stat_buf.st_size == 0) return 0;

    // if file size is too big return error code
    if(stat_buf.st_size > 31) return -2;
    if(stat_buf.st_size < sizeof(int)) return -2;

    // open file
    fp = fopen(last_serial_file, "rb");
    if(!fp)
    {
        perror("Error in get_sequence_number()");
        return -2;
    }

    size = fread(buff, 1, stat_buf.st_size, fp);
    fclose(fp);

    if(size != stat_buf.st_size)
    {
        perror("Error in get_sequence_number()");
        return -3;
    }

    buff[size] = 0;

    // now we have to see is it binary or ascii file
    if(size <= sizeof(int) + 1) value = *(int*)buff;
    else value  = strtol(buff, 0, 10);

    return value;
}


// backup old sequence number and set new one
// returns 0 or negative error code
int set_sequence_number(char* last_serial_file, int old_value, int new_value)
{
    FILE *fp;
    int size, v;
    char bkp_file_name[MAX_PATH];

    if(!last_serial_file) return -1;

    // make backup file
    strcpy(bkp_file_name, last_serial_file);
    strcat(bkp_file_name, ".bkp");

    fp = fopen(bkp_file_name, "wb");
    if(!fp)
    {
        perror("Error in set_sequence_number()");
        return -2;
    }
    size = fprintf(fp, "%010d", old_value);
    fclose(fp);

    fp = fopen(last_serial_file, "wb");
    if(!fp)
    {
        // can't open last_serial_file file
        //fprintf(stderr, "Can't open file '%s' for 'r+b', errno: %d\n", last_serial_file, errno);
        perror("Error in set_sequence_number()");
        return -2;
    }

    size = fprintf(fp, "%010d", new_value);
    fclose(fp);
    if(size != 10)
    {
        // fprintf() failed
        remove(last_serial_file);
        return -3;
    }
    return 0; // ok
}



// function to generate the actual serial number and put it into
// an intel hex record ready for programming
// outputfile = handle of file to write hex record
int generate(FILE *outputfile, hex_cfg* cfg)
{
	char hexrecord[MAX_SERIAL_SIZE * 3 + 20];
	struct tm* timedate;
	int old_seq, new_seq;
	time_t now;

	if(cfg->force) old_seq = cfg->sequence;
	else old_seq = get_sequence_number(cfg->last_serial_file);

    if(old_seq < 0) return old_seq; // error

    new_seq = old_seq;
    if(cfg->increment) new_seq = old_seq + 1;

    // ako se apdejtuje upisuje se nova vrijednost u registry
	if(cfg->update)
	{
		int err = set_sequence_number(cfg->last_serial_file, old_seq, new_seq);
		if(err < 0) return err;
	}

	// get the current time
	now = time(0);
	timedate = localtime(&now);

	// store current time in serial number array
	if(cfg->serialprefix)
	{
        sprintf(
            cfg->serialnumber,
            "%s-%04d%02d%02d%02d%02d%02d-%06u",
            cfg->serialprefix,
            1900 + timedate->tm_year,
            1 + timedate->tm_mon,
            timedate->tm_mday,
            timedate->tm_hour,
            timedate->tm_min,
            timedate->tm_sec,
            new_seq);
	}
	else
	{
        sprintf(
            cfg->serialnumber,
            "%04d%02d%02d%02d%02d%02d-%06u",
            1900 + timedate->tm_year,
            1 + timedate->tm_mon,
            timedate->tm_mday,
            timedate->tm_hour,
            timedate->tm_min,
            timedate->tm_sec,
            new_seq);
	}

	// create a hex record holding the serial number
	if(outputfile)
	{
        hexfile_generate_record( cfg->address, strlen(cfg->serialnumber) + 1,
            cfg->serialnumber, hexrecord);

        // output the hex record
        fprintf(outputfile, "%s\n", hexrecord);
	}

	return 0; // OK
}


void usage(void)
{
    fprintf(stderr,"HexSerial-%s, version %s, compiled at %s\n", VERSION_STRING, VERSION_STRING, __DATE__);
	fprintf(stderr,"Usage: -a n -l f -h f -p f -t f -i -u -f n -? --help\n");
	fprintf(stderr,"Options (all of them are optional):\n");
	fprintf(stderr,"  -i     increment sequence number\n");
	fprintf(stderr,"  -u     update last sequence file with forced value\n");
	fprintf(stderr,"  -a n   serial string address in HEX file in HEX notation with 0x prefix\n");
	fprintf(stderr,"  -f n   force sequence number to n\n");
	fprintf(stderr,"  -l f   last sequence file f\n");
	fprintf(stderr,"  -h f   output hex file f\n");
	fprintf(stderr,"  -t f   output text file f\n");
	fprintf(stderr,"  -p f   serial prefix\n");
	fprintf(stderr,"  -?     this help\n");
	fprintf(stderr,"  --help this help\n");
	fprintf(stderr,"Permitted combinations for -i -f -u operations:\n");
	fprintf(stderr,"  ifu\n");
	fprintf(stderr,"  000: re-make last serial\n");
    fprintf(stderr,"  001: not permitted\n");
    fprintf(stderr,"  010: force sequence number and make serial\n");
    fprintf(stderr,"  011: force sequence number, make serial and update last-sequence file\n");
    fprintf(stderr,"  100: increment last sequence number and make serial\n");
    fprintf(stderr,"  101: increment last sequence number, make serial and update last-sequence file\n");
    fprintf(stderr,"  110: not permitted\n");
    fprintf(stderr,"  111: not permitted\n");
	fprintf(stderr,"On error exit code is 1, on success exit code is 0\n");
	fprintf(stderr,"\n");
}


// main function
int main(int argc, char **argv)
{
	FILE *datafile = 0;
	hex_cfg cfg;
	int i;

	hex_cfg_init(&cfg);

	for(i = 0; i < argc; i++)
	{
		if(argv[i][0] == '-')
		{
			if(argv[i][1] == 'i') cfg.increment = 1;
			else if(argv[i][1] == 'l')
			{
			    if(argv[i][2] != 0) // -l<file>
				{
					cfg.last_serial_file = &argv[i][2];
				}
				else if(i + 1 < argc && argv[i + 1][0] != '-') // -l <file>
				{
					cfg.last_serial_file = argv[i + 1];
					i++;
				}
			}
			else if(argv[i][1] == 'h')
			{
			    if(argv[i][2] != 0) // -h<file>
				{
					cfg.datafilepath = &argv[i][2];
				}
				else if(i + 1 < argc && argv[i + 1][0] != '-') // -h <file>
				{
					cfg.datafilepath = argv[i + 1];
					i++;
				}
			}
			else if(argv[i][1] == 't')
			{
			    if(argv[i][2] != 0) // -t<file>
				{
					cfg.userfilepath = &argv[i][2];
				}
				else if(i + 1 < argc && argv[i + 1][0] != '-') // -t <file>
				{
					cfg.userfilepath = argv[i + 1];
					i++;
				}
			}
			else if(argv[i][1] == 'a')
			{
			    if(strncmp(argv[i], "-a0x", 4) == 0) // -a0x<addr>
			    {
					sscanf(argv[i],"-a0x%x",(unsigned int*)&cfg.address);
				}
				else if(argv[i][2] != 0) // -a<addr>
				{
				    sscanf(argv[i],"-a%d",(unsigned int*)&cfg.address);
				}
				else if(i + 1 < argc && argv[i + 1][0] != '-') // -a <file>
				{
				    if(strncmp(argv[i + 1], "0x", 2) == 0)
                        sscanf(argv[i + 1],"0x%x",(unsigned int*)&cfg.address);
                    else sscanf(argv[i + 1],"%d",(unsigned int*)&cfg.address);
					i++;
				}
			}
			else if(argv[i][1] == 'p')
			{
			    if(argv[i][2] != 0) // -p<file>
				{
					cfg.serialprefix = &argv[i][2];
				}
				else if(i + 1 < argc && argv[i + 1][0] != '-') // -p <file>
				{
					cfg.serialprefix = argv[i + 1];
					i++;
				}
			}
			else if(argv[i][1] == 'f') // force
			{
				if(argv[i][2] != 0) // -f<sequence>
				{
					cfg.sequence = strtoul(&argv[i][2],0,0);
				}
				else if(i + 1 < argc && argv[i + 1][0] != '-') // -f <sequence>
				{
					cfg.sequence = strtoul(argv[i + 1],0,0);
					i++;
				}
				if(cfg.sequence && cfg.sequence != 0xffffffffUL) cfg.force = 1;
			}
			else if(argv[i][1] == 'u') cfg.update = 1;
			else if(argv[i][1] == '?' || strcmp(argv[i], "--help") == 0) // help
			{
				usage();
				return 0;
			}
			// ignoring unknown command line options
			else ;
		}
	}

	if(cfg.address == 0 && cfg.datafilepath != 0)
	{
	    fprintf(stderr, "Invalid patch address\n");
	    return 1;
	}

    if(cfg.last_serial_file == 0)
	{
	    fprintf(stderr, "Last sequence file path invalid or missing\n");
	    return 1;
	}

    if(cfg.increment == 0 && cfg.force == 0 && cfg.update == 1)
	{
	    fprintf(stderr, "-u not permitted without -i or -f\n");
	    usage();
	    return 1;
	}
    if(cfg.increment == 1 && cfg.force == 1)
    {
        fprintf(stderr, "-i and -f are mutualy exlusive\n");
	    usage();
	    return 1;
    }


	// create file for hex records and generate records
	if(cfg.datafilepath)
	{
        datafile = fopen(cfg.datafilepath, "wb");
        if(!datafile)
        {
            fprintf(stderr, "Can't open file %s\n", cfg.datafilepath);
            return 1;
        }
	}

	if((i = generate(datafile, &cfg)) < 0)
	{
	    fprintf(stderr, "Can't generate HEX patch. ErrorCode %d\n", i);
	    if(datafile) fclose(datafile);
	    return 1; // FAIL
	}

	if(datafile) fclose(datafile);

	// create file for user output and put something in there
	if(cfg.userfilepath)
	{
        FILE* userfile = fopen(cfg.userfilepath, "w");
        if(!userfile)
        {
            fprintf(stderr, "Can't open file %s\n", cfg.userfilepath);
            return 1;
        }

        // generate some feedback for the user
        // in this case we tell the user what the serial number is generated
        // so it can be noted and maybe put on a sticker somewhere
        fprintf(userfile, "%s\n", cfg.serialnumber);
        fclose(userfile);
	}

	// print serial to stdio, so it could be catched by shell script or make
	printf("%s\n", cfg.serialnumber);

	// done
	return 0;
}

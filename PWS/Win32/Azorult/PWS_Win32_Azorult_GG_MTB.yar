
rule PWS_Win32_Azorult_GG_MTB{
	meta:
		description = "PWS:Win32/Azorult.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0e 00 00 "
		
	strings :
		$a_80_0 = {54 65 6c 65 67 72 61 6d } //Telegram  1
		$a_80_1 = {43 6f 69 6e 73 } //Coins  1
		$a_80_2 = {4d 6f 6e 65 72 6f } //Monero  1
		$a_80_3 = {50 61 73 73 77 6f 72 64 73 4c 69 73 74 } //PasswordsList  1
		$a_80_4 = {4d 61 63 68 69 6e 65 49 44 } //MachineID  1
		$a_80_5 = {45 58 45 5f 50 41 54 48 } //EXE_PATH  1
		$a_80_6 = {53 63 72 65 65 6e 3a } //Screen:  1
		$a_80_7 = {53 63 72 65 65 6e 53 68 6f 74 } //ScreenShot  1
		$a_80_8 = {5c 43 6f 6e 66 69 67 5c 2a 2e 76 64 66 } //\Config\*.vdf  1
		$a_80_9 = {2e 6b 65 79 73 } //.keys  1
		$a_80_10 = {5c 2e 70 75 72 70 6c 65 5c 61 63 63 6f 75 6e 74 73 2e 78 6d 6c } //\.purple\accounts.xml  1
		$a_80_11 = {53 45 4c 45 43 54 20 44 41 54 45 54 49 4d 45 28 6d 6f 7a 5f 68 69 73 74 6f 72 79 76 69 73 69 74 73 2e 76 69 73 69 74 5f 64 61 74 65 2f 31 30 30 30 30 30 30 2c 20 22 75 6e 69 78 65 70 6f 63 68 22 2c 20 22 6c 6f 63 61 6c 74 69 6d 65 22 29 2c } //SELECT DATETIME(moz_historyvisits.visit_date/1000000, "unixepoch", "localtime"),  1
		$a_80_12 = {6d 6f 7a 5f 70 6c 61 63 65 73 2e 74 69 74 6c 65 2c 6d 6f 7a 5f 70 6c 61 63 65 73 2e 75 72 6c 20 46 52 4f 4d 20 6d 6f 7a 5f 70 6c 61 63 65 73 2c } //moz_places.title,moz_places.url FROM moz_places,  1
		$a_80_13 = {53 45 4c 45 43 54 20 44 41 54 45 54 49 4d 45 28 20 28 28 76 69 73 69 74 73 2e 76 69 73 69 74 5f 74 69 6d 65 2f 31 30 30 30 30 30 30 29 2d 31 31 36 34 34 34 37 33 36 30 30 29 2c 22 75 6e 69 78 65 70 6f 63 68 22 29 20 2c 20 75 72 6c 73 2e 74 69 74 6c 65 20 2c 20 75 72 6c 73 2e 75 72 6c 20 46 52 4f 4d 20 75 72 6c 73 2c 20 76 69 73 69 74 73 20 57 48 45 52 45 20 75 72 6c 73 2e 69 64 } //SELECT DATETIME( ((visits.visit_time/1000000)-11644473600),"unixepoch") , urls.title , urls.url FROM urls, visits WHERE urls.id  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1) >=10
 
}
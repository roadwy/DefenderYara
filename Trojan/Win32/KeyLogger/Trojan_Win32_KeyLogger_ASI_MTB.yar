
rule Trojan_Win32_KeyLogger_ASI_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {33 33 30 31 4b 69 72 61 } //1 3301Kira
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 64 00 65 00 66 00 39 00 62 00 36 00 63 00 64 00 33 00 66 00 32 00 62 00 30 00 63 00 34 00 33 00 30 00 39 00 37 00 64 00 66 00 62 00 63 00 39 00 31 00 38 00 38 00 36 00 32 00 62 00 38 00 32 00 } //1 Software\def9b6cd3f2b0c43097dfbc918862b82
		$a_01_2 = {44 43 5f 4d 55 54 45 58 2d 34 57 54 4c 34 5a 52 } //1 DC_MUTEX-4WTL4ZR
		$a_01_3 = {4b 65 79 6c 6f 67 67 65 72 20 69 73 20 75 70 20 61 6e 64 20 72 75 6e 6e 69 6e 67 } //1 Keylogger is up and running
		$a_01_4 = {44 4e 5d 00 5b 45 4e 44 5d 00 00 00 5b 48 4f 4d 45 5d 00 00 5b 4c 45 46 54 5d 00 00 5b 52 49 47 48 54 5d 00 5b 44 4f 57 4e 5d 00 00 5b 50 52 49 4e 54 5d 00 5b 50 52 54 20 53 43 5d 00 00 00 00 5b 49 4e 53 45 52 54 5d 00 00 00 00 5b 44 45 4c 45 54 45 5d 00 00 00 00 5b 57 49 4e 20 4b 45 59 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule Trojan_Win32_KeyLogger_ASI_MTB_2{
	meta:
		description = "Trojan:Win32/KeyLogger.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 65 72 6d 61 6e } //1 killerman
		$a_01_1 = {76 00 62 00 6e 00 62 00 6e 00 62 00 76 00 2c 00 62 00 6e 00 6e 00 62 00 6e 00 76 00 76 00 6e 00 2c 00 74 00 79 00 72 00 67 00 67 00 67 00 2c 00 71 00 77 00 77 00 77 00 77 00 65 00 65 00 65 00 65 00 2c 00 69 00 6f 00 75 00 79 00 75 00 74 00 72 00 } //1 vbnbnbv,bnnbnvvn,tyrggg,qwwwweeee,iouyutr
		$a_01_2 = {66 00 6b 00 2e 00 65 00 78 00 65 00 } //1 fk.exe
		$a_01_3 = {5d 00 6e 00 77 00 6f 00 44 00 65 00 67 00 61 00 50 00 5b 00 } //1 ]nwoDegaP[
		$a_01_4 = {5d 00 65 00 6d 00 6f 00 48 00 5b 00 } //1 ]emoH[
		$a_01_5 = {5b 00 20 00 41 00 4c 00 54 00 44 00 4f 00 57 00 4e 00 20 00 5d 00 } //1 [ ALTDOWN ]
		$a_01_6 = {61 00 39 00 65 00 77 00 36 00 34 00 6a 00 73 00 7a 00 6a 00 68 00 37 00 30 00 67 00 74 00 39 00 30 00 39 00 63 00 30 00 6a 00 69 00 39 00 6c 00 6e 00 32 00 62 00 6d 00 31 00 75 00 6d 00 32 00 37 00 69 00 30 00 30 00 61 00 33 00 68 00 65 00 70 00 6a 00 31 00 34 00 34 00 65 00 6d 00 74 00 68 00 74 00 } //1 a9ew64jszjh70gt909c0ji9ln2bm1um27i00a3hepj144emtht
		$a_01_7 = {63 00 2e 00 65 00 78 00 65 00 20 00 2d 00 6f 00 20 00 } //1 c.exe -o 
		$a_01_8 = {77 00 65 00 72 00 65 00 77 00 72 00 77 00 77 00 77 00 77 00 77 00 77 00 } //1 werewrwwwwww
		$a_01_9 = {53 00 20 00 20 00 75 00 20 00 20 00 72 00 20 00 20 00 65 00 } //1 S  u  r  e
		$a_01_10 = {41 00 72 00 65 00 20 00 20 00 59 00 6f 00 75 00 20 00 20 00 20 00 53 00 75 00 72 00 65 00 20 00 20 00 20 00 59 00 6f 00 75 00 20 00 20 00 20 00 57 00 61 00 6e 00 74 00 20 00 54 00 6f 00 20 00 20 00 52 00 65 00 2d 00 73 00 65 00 74 00 20 00 54 00 69 00 6d 00 65 00 72 00 3f 00 3f 00 3f 00 } //1 Are  You   Sure   You   Want To  Re-set Timer???
		$a_01_11 = {4c 00 6f 00 67 00 20 00 53 00 75 00 62 00 6d 00 69 00 74 00 74 00 65 00 64 00 21 00 } //1 Log Submitted!
		$a_01_12 = {6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //1 log.txt
		$a_01_13 = {61 00 63 00 68 00 69 00 62 00 61 00 74 00 } //1 achibat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}

rule Constructor_Win32_Kiratzki_A{
	meta:
		description = "Constructor:Win32/Kiratzki.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {52 61 74 45 78 74 72 61 63 74 6f 72 } //2 RatExtractor
		$a_01_1 = {52 61 74 43 65 6e 74 65 72 } //2 RatCenter
		$a_01_2 = {52 61 74 44 65 63 72 79 70 74 6f 72 } //2 RatDecryptor
		$a_01_3 = {46 69 6c 65 43 6f 6e 6e 65 63 74 6f 72 2e 65 78 65 } //2 FileConnector.exe
		$a_01_4 = {74 68 65 72 61 74 2e 68 31 35 2e 72 75 } //2 therat.h15.ru
		$a_01_5 = {41 4c 4c 20 41 43 54 49 56 49 54 49 45 53 20 4f 4e 20 54 48 49 53 20 53 59 53 54 45 4d 20 41 52 45 20 4d 4f 4e 49 54 4f 52 45 44 } //1 ALL ACTIVITIES ON THIS SYSTEM ARE MONITORED
		$a_01_6 = {48 61 6e 64 79 43 61 74 } //1 HandyCat
		$a_01_7 = {63 3a 5c 72 61 74 2e 64 61 74 } //1 c:\rat.dat
		$a_01_8 = {54 68 65 20 52 61 74 21 } //1 The Rat!
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
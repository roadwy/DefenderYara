
rule Trojan_Win32_Guloader_ASL_MTB{
	meta:
		description = "Trojan:Win32/Guloader.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 65 73 72 69 76 65 6c 73 65 6e 2e 65 78 65 } //1 loesrivelsen.exe
		$a_01_1 = {48 79 6c 64 65 62 75 73 6b 65 6e 65 5c 70 72 6f 64 75 6b 74 69 6f 6e 73 72 65 67 65 6c 73 2e 67 69 66 } //1 Hyldebuskene\produktionsregels.gif
		$a_01_2 = {52 65 67 69 6d 65 6e 74 73 73 74 61 62 65 31 37 30 5c 76 69 61 6e 6e 61 73 2e 6c 6e 6b } //1 Regimentsstabe170\viannas.lnk
		$a_01_3 = {41 6c 61 72 6d 69 6a 72 31 38 34 5c 67 6f 72 6d 61 6e 64 69 7a 69 6e 67 2e 69 6e 69 } //1 Alarmijr184\gormandizing.ini
		$a_01_4 = {76 69 74 75 70 65 72 5c 76 65 63 74 6f 72 69 61 6c 6c 79 2e 6a 70 67 } //1 vituper\vectorially.jpg
		$a_01_5 = {6d 79 73 74 69 66 69 6b 61 74 69 6f 6e 65 72 6e 65 73 2e 73 6f 75 } //1 mystifikationernes.sou
		$a_01_6 = {5a 65 72 65 62 61 31 32 2e 74 78 74 } //1 Zereba12.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
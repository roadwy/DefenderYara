
rule Trojan_Win32_Gedese_YA_MTB{
	meta:
		description = "Trojan:Win32/Gedese.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 00 67 00 65 00 74 00 5f 00 76 00 32 00 2e 00 70 00 68 00 70 00 } //1 /get_v2.php
		$a_01_1 = {2f 00 2f 00 61 00 70 00 69 00 2e 00 32 00 69 00 70 00 2e 00 75 00 61 00 2f 00 67 00 65 00 6f 00 2e 00 6a 00 73 00 6f 00 6e 00 } //3 //api.2ip.ua/geo.json
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //3 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {64 65 6c 73 65 6c 66 2e 62 61 74 } //1 delself.bat
		$a_01_4 = {22 63 6f 75 6e 74 72 79 5f 63 6f 64 65 22 3a 22 } //1 "country_code":"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}
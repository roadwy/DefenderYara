
rule Trojan_BAT_XWorm_BSA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 04 00 00 "
		
	strings :
		$a_01_0 = {5a 57 4d 32 4d 7a 4a 6d 5a 44 6b 74 4d 54 59 35 4e 43 30 30 5a 6a 52 68 4c 54 6c 69 5a 6d 59 74 5a 6a 49 77 4e 6a 41 77 5a 54 4d 33 4f 54 67 78 } //10 ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx
		$a_01_1 = {31 38 35 2e 37 2e 32 31 34 2e 31 30 38 2f 61 2e 65 78 65 } //10 185.7.214.108/a.exe
		$a_01_2 = {4c 6f 61 64 4f 50 } //10 LoadOP
		$a_81_3 = {61 48 52 30 63 44 6f 76 4c 7a 45 34 4e 53 34 33 4c 6a 49 78 4e 43 34 78 4d 44 67 76 59 53 35 6c 65 47 55 } //6 aHR0cDovLzE4NS43LjIxNC4xMDgvYS5leGU
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_81_3  & 1)*6) >=36
 
}
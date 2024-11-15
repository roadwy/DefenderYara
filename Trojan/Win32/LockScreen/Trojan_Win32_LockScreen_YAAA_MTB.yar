
rule Trojan_Win32_LockScreen_YAAA_MTB{
	meta:
		description = "Trojan:Win32/LockScreen.YAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 48 52 30 63 44 6f 76 4c 7a 49 78 4d 43 34 78 4d 6a 63 75 4d 54 67 34 4c 6a 49 30 4d 44 6f 34 4d 44 67 7a 4c 33 64 6c 62 47 4e 76 62 57 55 75 5a 47 38 3d } //4 aHR0cDovLzIxMC4xMjcuMTg4LjI0MDo4MDgzL3dlbGNvbWUuZG8=
		$a_01_1 = {52 61 6e 73 6f 6d 65 77 61 72 65 } //2 Ransomeware
		$a_01_2 = {69 73 52 61 6e 73 6f 6d 65 50 6f 70 75 70 } //2 isRansomePopup
		$a_01_3 = {72 61 6e 73 6f 6d 65 45 6e 63 50 61 74 68 } //1 ransomeEncPath
		$a_01_4 = {5c 21 21 21 21 21 52 45 41 44 4d 45 2e 74 78 74 } //1 \!!!!!README.txt
		$a_01_5 = {4f 72 69 67 69 6e 20 4d 61 6c 77 61 72 65 20 53 74 61 72 74 } //3 Origin Malware Start
		$a_01_6 = {4d 61 6c 77 61 72 65 20 52 75 6e 6e 69 6e 67 2e 2e } //3 Malware Running..
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3) >=16
 
}
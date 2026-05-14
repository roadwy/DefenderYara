
rule Trojan_Win64_Amadey_PAHA_MTB{
	meta:
		description = "Trojan:Win64/Amadey.PAHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {25 4c 4f 43 41 4c 41 50 50 44 41 54 41 25 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //2 %LOCALAPPDATA%\Google\Chrome\User Data
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 } //2 Microsoft\Edge\User Data
		$a_01_2 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 } //1 net localgroup Administrators
		$a_01_3 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 20 65 78 63 6c 75 73 69 6f 6e 73 } //2 Windows Defender exclusions
		$a_01_4 = {63 6f 6f 6b 69 65 73 } //1 cookies
		$a_01_5 = {77 61 6c 6c 65 74 73 } //1 wallets
		$a_01_6 = {2f 75 70 6c 6f 61 64 2e 70 68 70 } //2 /upload.php
		$a_01_7 = {68 69 73 74 6f 72 79 } //1 history
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1) >=12
 
}
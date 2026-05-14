
rule PWS_Win64_WallStealer_CI_MTB{
	meta:
		description = "PWS:Win64/WallStealer.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 45 4c 45 43 54 20 4e 61 6d 65 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 6f 72 } //2 SELECT Name FROM Win32_Processor
		$a_01_1 = {53 45 4c 45 43 54 20 4e 61 6d 65 20 46 52 4f 4d 20 57 69 6e 33 32 5f 56 69 64 65 6f 43 6f 6e 74 72 6f 6c 6c 65 72 } //2 SELECT Name FROM Win32_VideoController
		$a_01_2 = {43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //2 Chrome\User Data
		$a_01_3 = {45 64 67 65 5c 55 73 65 72 20 44 61 74 61 } //2 Edge\User Data
		$a_01_4 = {4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 } //2 Mozilla Firefox
		$a_01_5 = {4f 70 65 72 61 20 53 74 61 62 6c 65 } //2 Opera Stable
		$a_01_6 = {42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 } //2 Brave-Browser\User Data
		$a_01_7 = {6c 6f 67 69 6e 75 73 65 72 73 } //2 loginusers
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=16
 
}
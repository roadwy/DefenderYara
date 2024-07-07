
rule Backdoor_Win32_Zegost_MC{
	meta:
		description = "Backdoor:Win32/Zegost.MC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 01 80 f3 62 88 18 40 90 01 01 75 f4 90 00 } //2
		$a_03_1 = {80 04 11 7a 03 ca 8b 4d 90 01 01 80 34 11 19 03 ca 90 00 } //1
		$a_01_2 = {83 f8 7f 77 11 83 f8 14 72 0c } //1
		$a_00_3 = {48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 6e 0d 0a 0d 0a 3c 62 6f 64 79 3e 3c 68 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 68 31 3e } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
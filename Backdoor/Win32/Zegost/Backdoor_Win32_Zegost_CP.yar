
rule Backdoor_Win32_Zegost_CP{
	meta:
		description = "Backdoor:Win32/Zegost.CP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 73 2c 53 75 6e 6e 79 00 } //1
		$a_01_1 = {50 7a 37 36 6d 38 76 50 71 39 42 51 49 44 39 50 73 45 76 51 44 38 2b 71 6d 6d 70 37 7a 76 39 72 33 35 37 77 53 66 00 } //1
		$a_00_2 = {c6 44 24 38 00 c6 44 24 3c 57 c6 44 24 3d 61 c6 44 24 40 46 c6 44 24 41 6f 88 54 24 42 c6 44 24 43 53 c6 44 24 45 6e c6 44 24 46 67 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}

rule Trojan_Win32_Alureon_FJ{
	meta:
		description = "Trojan:Win32/Alureon.FJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b c5 8b 13 8b ca c1 e1 09 be 53 46 00 00 66 89 34 39 } //2
		$a_01_1 = {0f b7 40 16 c1 e8 0d 83 e0 01 75 } //2
		$a_01_2 = {b9 ff df 00 00 66 21 4e 16 8d 54 24 } //2
		$a_01_3 = {50 75 72 70 6c 65 48 61 7a 65 } //1 PurpleHaze
		$a_01_4 = {5c 5c 2e 5c 67 6c 6f 62 61 6c 72 6f 6f 74 25 73 5c 70 68 } //1 \\.\globalroot%s\ph
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}
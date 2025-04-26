
rule Trojan_Win32_Alureon_FO{
	meta:
		description = "Trojan:Win32/Alureon.FO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 13 8b 75 10 8b c2 c1 e0 09 b9 53 46 00 00 66 89 0c 38 } //2
		$a_01_1 = {0f b7 48 16 33 c0 c1 e9 0d 40 23 c8 75 } //2
		$a_01_2 = {b8 ff df 00 00 66 21 47 16 } //2
		$a_01_3 = {50 75 72 70 6c 65 48 61 7a 65 } //1 PurpleHaze
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=3
 
}
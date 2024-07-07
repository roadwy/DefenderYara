
rule Trojan_Win32_Alureon_FT{
	meta:
		description = "Trojan:Win32/Alureon.FT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 0a 33 d2 59 f7 f1 83 fa 01 73 05 e8 90 01 04 68 e8 03 00 00 ff 15 90 01 04 8b 4d 08 90 00 } //1
		$a_03_1 = {83 e8 05 89 45 90 01 01 8b 45 14 8d 3c 1e c6 45 90 01 01 e9 8d 75 90 01 01 a5 a4 8b 7d fc 89 18 8b 45 10 2b c7 83 e8 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}

rule Trojan_Win32_Upatre_MA_MTB{
	meta:
		description = "Trojan:Win32/Upatre.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 c4 18 33 c0 50 68 80 00 00 00 6a 03 50 6a 01 68 00 00 00 80 57 ff 93 } //3
		$a_01_1 = {89 45 dc 6a 00 8d 4d e0 51 56 ff 75 e4 50 ff 93 } //3
		$a_01_2 = {8b 45 fc c1 e1 02 03 c1 8b 00 c3 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=9
 
}
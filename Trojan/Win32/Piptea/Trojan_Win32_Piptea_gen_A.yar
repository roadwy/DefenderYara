
rule Trojan_Win32_Piptea_gen_A{
	meta:
		description = "Trojan:Win32/Piptea.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 90 01 04 50 58 c3 90 00 } //1
		$a_02_1 = {66 81 38 4d 5a 90 02 10 81 3c 01 50 45 00 00 74 07 2d 00 00 01 00 90 00 } //1
		$a_02_2 = {8d 45 f4 50 6a 01 8d 45 ff 50 53 89 7d f4 90 02 10 ff 15 90 01 04 03 75 f4 ff 4d f8 75 90 01 01 53 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
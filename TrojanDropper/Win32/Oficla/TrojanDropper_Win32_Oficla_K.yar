
rule TrojanDropper_Win32_Oficla_K{
	meta:
		description = "TrojanDropper:Win32/Oficla.K,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_03_0 = {89 5c 24 08 c7 44 24 04 90 01 04 c7 04 24 90 01 04 e8 90 09 03 00 83 ec 0c 90 00 } //5
		$a_03_1 = {c7 04 24 04 01 00 00 90 09 04 00 89 90 01 01 24 04 90 00 } //5
		$a_01_2 = {c7 04 24 00 40 40 00 e8 0e 00 00 00 52 c9 c3 } //5
		$a_01_3 = {a1 ef 54 15 c6 a2 a6 5f 45 90 a3 90 f8 34 98 c4 c9 9b 20 65 fc 8d 89 } //1
		$a_01_4 = {a5 ef 54 12 c6 a5 af 5f 45 90 aa 90 f5 34 98 ca cd 9b 20 62 fc 8a 80 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=16
 
}

rule Ransom_Win32_Conti_ZF{
	meta:
		description = "Ransom:Win32/Conti.ZF,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {8d 45 f8 50 ba 90 01 04 e8 90 01 04 a3 90 01 04 83 c4 04 90 00 } //0a 00 
		$a_03_2 = {68 00 10 00 00 e8 90 01 04 a3 90 01 04 83 c4 04 90 00 } //0a 00 
		$a_03_3 = {8b 0e 03 ca 33 d2 38 11 74 0d 66 0f 1f 44 00 00 42 80 3c 0a 00 75 f9 51 e8 90 01 04 83 c4 04 3b 45 f4 74 24 8b 45 fc 47 8b 55 f8 83 c6 04 83 c3 02 3b 78 18 72 c9 90 00 } //00 00 
		$a_00_4 = {5d 04 00 00 80 ec 04 80 5c 2b 00 00 81 ec 04 80 00 00 01 00 32 00 15 00 52 61 6e 73 6f 6d } //3a 57 
	condition:
		any of ($a_*)
 
}
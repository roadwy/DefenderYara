
rule Trojan_Win32_Fareit_N_MTB{
	meta:
		description = "Trojan:Win32/Fareit.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {d9 d0 8b 04 0a 01 f3 0f 6e c0 0f 6e 0b 0f ef c1 51 0f 7e c1 88 c8 59 29 f3 83 c3 01 75 02 89 fb 89 04 0a 83 c1 01 75 d8 } //01 00 
		$a_01_1 = {81 ec 00 02 00 00 55 89 e5 e8 00 00 00 00 58 83 e8 0e 89 45 44 e8 9e 27 00 00 85 c9 e9 b5 19 00 00 59 89 4d 18 39 c9 b8 39 05 00 00 ba 6d 07 af 60 e8 a9 22 00 00 89 85 98 00 00 00 e9 b1 19 00 00 fc 59 ba c5 dc cf 94 e8 92 22 00 00 eb 1c 85 ff 5b 31 d2 52 54 53 85 db ff d0 58 83 f8 0c 7d 20 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_N_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 55 00 41 00 57 00 45 00 41 00 } //01 00  hUAWEA
		$a_01_1 = {44 00 41 00 43 00 20 00 74 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 4f 00 67 00 49 00 45 00 53 00 } //01 00  DAC technolOgIES
		$a_01_2 = {43 00 41 00 6d 00 20 00 73 00 54 00 55 00 44 00 49 00 4f 00 20 00 67 00 72 00 6f 00 75 00 4f 00 } //01 00  CAm sTUDIO grouO
		$a_01_3 = {53 00 4f 00 55 00 52 00 43 00 6f 00 20 00 66 00 49 00 52 00 41 00 2c 00 20 00 67 00 6e 00 72 00 2e 00 } //01 00  SOURCo fIRA, gnr.
		$a_01_4 = {57 00 4f 00 52 00 6c 00 65 00 } //01 00  WORle
		$a_01_5 = {5a 00 41 00 4c 00 4c 00 4f 00 20 00 43 00 52 00 65 00 20 00 4a 00 65 00 63 00 61 00 } //00 00  ZALLO CRe Jeca
	condition:
		any of ($a_*)
 
}
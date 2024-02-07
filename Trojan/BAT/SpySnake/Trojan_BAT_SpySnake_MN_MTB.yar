
rule Trojan_BAT_SpySnake_MN_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 51 00 00 00 08 00 00 00 30 00 00 00 2b 00 00 00 24 00 00 00 85 00 00 00 16 } //05 00 
		$a_01_1 = {64 38 65 38 61 62 35 30 2d 31 61 30 31 2d 34 65 32 62 2d 38 62 61 36 2d 62 38 64 30 33 65 39 66 65 62 64 62 } //01 00  d8e8ab50-1a01-4e2b-8ba6-b8d03e9febdb
		$a_01_2 = {4a 61 6d 62 6f } //01 00  Jambo
		$a_01_3 = {4b 75 72 73 6f 76 61 79 61 5f 54 61 6e 63 68 69 6b 69 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  Kursovaya_Tanchiki.Properties
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_5 = {46 6f 72 6d 32 5f 4b 65 79 44 6f 77 6e } //00 00  Form2_KeyDown
	condition:
		any of ($a_*)
 
}
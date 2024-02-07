
rule Trojan_BAT_LokiBot_FJ_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.FJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 1f a2 09 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 83 00 00 00 28 } //01 00 
		$a_01_1 = {24 30 64 31 34 61 31 33 61 2d 37 65 30 64 2d 34 30 66 32 2d 39 32 32 33 2d 61 66 36 37 66 65 30 34 35 31 37 32 } //01 00  $0d14a13a-7e0d-40f2-9223-af67fe045172
		$a_01_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_4 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_01_5 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}
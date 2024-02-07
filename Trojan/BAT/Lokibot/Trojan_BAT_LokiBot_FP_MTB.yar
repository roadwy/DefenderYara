
rule Trojan_BAT_LokiBot_FP_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.FP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 1f a2 0b 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 b0 00 00 00 4e 00 00 00 dc 00 00 00 92 } //01 00 
		$a_01_1 = {24 34 39 66 65 32 34 38 35 2d 31 63 33 63 2d 34 32 66 65 2d 62 61 66 64 2d 39 35 61 61 30 38 31 34 63 33 31 66 } //01 00  $49fe2485-1c3c-42fe-bafd-95aa0814c31f
		$a_01_2 = {50 65 72 66 54 65 73 74 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  PerfTester.Properties.Resources.resources
		$a_01_3 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_01_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_5 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}

rule TrojanDropper_Win32_Small_gen_N{
	meta:
		description = "TrojanDropper:Win32/Small.gen!N,SIGNATURE_TYPE_PEHSTR,21 00 15 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 56 05 00 0a 00 00 } //0a 00 
		$a_01_1 = {56 50 8d 85 10 6b fb ff 68 00 0e 00 00 50 ff 75 f8 } //0a 00 
		$a_01_2 = {56 50 bb 0e cb 00 00 8d 85 10 6b fb ff 53 50 } //01 00 
		$a_01_3 = {62 6f 6f 6b 2e 65 78 65 } //01 00 
		$a_01_4 = {62 6f 6f 6b 2e 70 64 66 } //01 00 
		$a_01_5 = {41 63 72 6f 52 64 33 32 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}
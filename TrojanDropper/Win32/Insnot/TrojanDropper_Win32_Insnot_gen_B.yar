
rule TrojanDropper_Win32_Insnot_gen_B{
	meta:
		description = "TrojanDropper:Win32/Insnot.gen!B,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 69 63 61 74 65 20 2d 20 41 64 75 6c 74 20 63 6f 64 65 63 } //01 00 
		$a_01_1 = {40 24 26 25 30 34 5c 63 6f 64 65 63 2e 65 78 65 } //01 00 
		$a_01_2 = {40 24 26 25 30 34 5c 6c 6f 61 64 65 72 6e 65 77 2e 65 78 65 } //01 00 
		$a_01_3 = {52 75 73 73 69 61 6e 20 28 } //01 00 
		$a_01_4 = {43 6f 64 65 63 3f } //00 00 
	condition:
		any of ($a_*)
 
}
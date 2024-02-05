
rule TrojanDropper_Win32_Swisyn_F{
	meta:
		description = "TrojanDropper:Win32/Swisyn.F,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 72 65 46 69 6c 65 41 70 69 73 41 64 2e 65 78 65 } //01 00 
		$a_01_1 = {42 74 73 20 61 6e 64 20 53 65 74 } //01 00 
		$a_01_2 = {2f 63 20 61 74 74 72 69 62 20 2d 52 20 2d 48 20 2d 53 20 22 25 73 22 } //01 00 
		$a_01_3 = {57 69 6e 64 6f 77 73 5c 25 73 2e 73 63 72 } //01 00 
		$a_01_4 = {50 69 6e 20 74 68 69 73 20 70 72 6f 67 72 61 6d 20 74 6f 20 74 61 73 6b 62 61 72 } //00 00 
	condition:
		any of ($a_*)
 
}
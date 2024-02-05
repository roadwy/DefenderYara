
rule TrojanDropper_Win32_Nonaco_D{
	meta:
		description = "TrojanDropper:Win32/Nonaco.D,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //02 00 
		$a_01_1 = {00 64 69 77 73 66 73 65 00 } //02 00 
		$a_01_2 = {25 73 25 73 00 61 6c 67 67 } //01 00 
		$a_01_3 = {3a 5c 74 6d 70 33 2e 72 65 67 00 } //01 00 
		$a_01_4 = {77 62 6c 6f 67 6f 6e 00 25 73 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}

rule TrojanDropper_Win32_Carberp_A{
	meta:
		description = "TrojanDropper:Win32/Carberp.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 61 65 6d 6f 6e 75 70 64 2e 65 78 65 20 2f 73 76 63 } //01 00 
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 77 69 6e 75 70 64 61 74 65 2e 65 78 65 } //01 00 
		$a_01_2 = {6e 76 55 70 64 53 65 72 76 69 63 65 } //01 00 
		$a_01_3 = {77 69 6e 75 70 64 61 74 65 2e 6c 6e 6b } //00 00 
	condition:
		any of ($a_*)
 
}
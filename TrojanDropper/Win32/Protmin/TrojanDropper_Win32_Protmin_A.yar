
rule TrojanDropper_Win32_Protmin_A{
	meta:
		description = "TrojanDropper:Win32/Protmin.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 52 6f 6f 74 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 25 73 2e 73 79 73 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 33 37 32 31 5c 41 75 74 6f 4c 69 76 65 } //01 00 
		$a_01_2 = {2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_3 = {50 61 74 63 68 5c 70 61 74 63 68 32 39 5c 73 79 73 } //00 00 
	condition:
		any of ($a_*)
 
}
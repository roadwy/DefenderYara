
rule TrojanDropper_Win32_Swisyn_C{
	meta:
		description = "TrojanDropper:Win32/Swisyn.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 79 70 73 51 75 6f 66 73 62 71 74 6f 62 73 55 6e 70 75 74 76 44 65 4a 63 } //01 00 
		$a_01_1 = {74 6d 70 64 70 75 70 73 51 74 68 6f 6a 73 75 54 66 64 73 76 70 74 66 53 65 4a 7c } //01 00 
		$a_01_2 = {74 6d 70 64 70 75 70 73 51 6d 62 63 70 6d 48 65 4a 75 } //01 00 
		$a_01_3 = {66 73 70 44 74 68 6f 6a 73 75 54 66 64 73 76 70 74 66 53 65 4a 63 } //00 00 
	condition:
		any of ($a_*)
 
}
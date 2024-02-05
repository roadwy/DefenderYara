
rule TrojanDropper_O97M_Donoff_AJK_MSR{
	meta:
		description = "TrojanDropper:O97M/Donoff.AJK!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {22 63 3a 5c 6e 65 74 73 74 61 74 73 5c 22 20 26 20 22 50 72 65 73 73 54 61 62 6c 65 4c 69 73 74 22 20 26 20 22 2e 6a 73 65 22 } //01 00 
		$a_00_1 = {22 63 3a 5c 6e 65 74 73 74 61 74 73 5c 22 20 26 20 22 50 72 65 73 73 54 61 62 6c 65 4c 69 73 74 22 20 26 20 22 2e 63 6d 64 22 } //01 00 
		$a_00_2 = {22 63 73 63 72 69 70 74 20 2f 2f 6e 6f 6c 6f 67 6f 20 22 20 2b 20 46 69 6c 65 6e 61 6d 65 } //01 00 
		$a_00_3 = {73 74 72 50 61 72 68 20 3d 20 22 63 3a 5c 6e 65 74 73 74 61 74 73 22 } //00 00 
	condition:
		any of ($a_*)
 
}
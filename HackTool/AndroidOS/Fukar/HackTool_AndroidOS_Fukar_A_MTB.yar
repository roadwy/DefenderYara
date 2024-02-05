
rule HackTool_AndroidOS_Fukar_A_MTB{
	meta:
		description = "HackTool:AndroidOS/Fukar.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_00_0 = {57 55 5a 48 52 45 59 4d 47 42 64 61 53 51 4d 48 45 51 55 66 43 52 46 47 43 67 55 47 51 77 77 65 42 46 38 55 45 41 6c 46 48 46 6c 48 57 6c 67 3d } //01 00 
		$a_00_1 = {63 79 62 65 72 2e 61 7a 6f 76 } //01 00 
		$a_00_2 = {73 74 61 72 74 5f 61 74 74 61 63 6b } //01 00 
		$a_00_3 = {44 64 6f 73 20 72 65 71 75 65 73 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}

rule HackTool_AndroidOS_Penetho_A_MTB{
	meta:
		description = "HackTool:AndroidOS/Penetho.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 65 6e 65 74 72 61 74 65 50 72 65 66 73 } //01 00 
		$a_00_1 = {52 65 76 65 72 73 65 42 72 6f 6b 65 72 } //01 00 
		$a_00_2 = {70 61 73 73 77 6f 72 64 5f 67 65 6e 65 72 61 74 69 6f 6e } //01 00 
		$a_01_3 = {4f 4f 50 53 5f 4e 4f 54 52 45 56 45 52 53 49 42 4c 45 } //01 00 
		$a_00_4 = {6f 72 67 2e 75 6e 64 65 72 64 65 76 2e 70 65 6e 65 74 72 61 74 65 70 72 6f } //00 00 
		$a_00_5 = {5d 04 00 00 } //e4 90 
	condition:
		any of ($a_*)
 
}
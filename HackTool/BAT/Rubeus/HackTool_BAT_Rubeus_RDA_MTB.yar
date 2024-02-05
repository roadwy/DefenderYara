
rule HackTool_BAT_Rubeus_RDA_MTB{
	meta:
		description = "HackTool:BAT/Rubeus.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 75 62 65 75 73 } //01 00 
		$a_01_1 = {6d 69 6e 69 62 65 75 73 } //01 00 
		$a_01_2 = {4b 72 62 43 72 65 64 49 6e 66 6f } //01 00 
		$a_01_3 = {41 73 6e 45 6c 74 } //01 00 
		$a_01_4 = {45 6e 63 72 79 70 74 65 64 50 41 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}
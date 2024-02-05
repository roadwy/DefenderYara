
rule VirTool_BAT_Subti_V_bit{
	meta:
		description = "VirTool:BAT/Subti.V!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 64 64 42 69 6e 64 65 64 46 69 6c 65 64 } //01 00 
		$a_01_1 = {46 69 6c 65 50 65 72 73 69 73 74 61 6e 63 65 } //01 00 
		$a_01_2 = {4d 6f 6e 69 74 6f 72 69 6e 67 53 65 6c 66 } //01 00 
		$a_01_3 = {52 65 67 50 65 72 73 69 73 74 61 6e 63 65 } //01 00 
		$a_01_4 = {52 65 63 6c 61 69 6d 4d 75 74 65 78 } //00 00 
	condition:
		any of ($a_*)
 
}
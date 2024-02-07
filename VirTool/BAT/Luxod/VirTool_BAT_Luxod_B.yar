
rule VirTool_BAT_Luxod_B{
	meta:
		description = "VirTool:BAT/Luxod.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 73 00 } //01 00  湁楴s
		$a_01_1 = {49 6e 6a 65 63 74 69 6f 6e 54 61 72 67 65 74 00 } //01 00  湉敪瑣潩呮牡敧t
		$a_01_2 = {44 69 73 61 62 6c 65 72 73 00 } //01 00  楄慳汢牥s
		$a_01_3 = {4d 65 6c 74 46 69 6c 65 00 } //01 00 
		$a_01_4 = {45 6e 61 62 6c 65 53 74 61 72 74 75 70 00 } //00 00  湅扡敬瑓牡畴p
		$a_00_5 = {5d 04 00 } //00 f7 
	condition:
		any of ($a_*)
 
}
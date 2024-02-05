
rule HackTool_Linux_Keimpx_gen_A{
	meta:
		description = "HackTool:Linux/Keimpx.gen!A!!Keimpx.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {4c 61 75 6e 63 68 69 6e 67 20 69 6e 74 65 72 61 63 74 69 76 65 20 53 4d 42 20 73 68 65 6c 6c } //01 00 
		$a_81_1 = {6b 65 69 6d 70 78 } //01 00 
		$a_81_2 = {62 69 6e 64 73 68 65 6c 6c 20 5b 70 6f 72 74 5d } //01 00 
		$a_81_3 = {73 76 63 73 68 65 6c 6c 20 5b 6d 6f 64 65 5d } //00 00 
	condition:
		any of ($a_*)
 
}
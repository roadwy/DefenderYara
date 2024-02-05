
rule HackTool_MacOS_Earthworm_B_MTB{
	meta:
		description = "HackTool:MacOS/Earthworm.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 6f 6f 74 6b 69 74 65 72 2e 63 6f 6d 2f 45 61 72 74 68 57 72 6f 6d 2f } //01 00 
		$a_00_1 = {2e 2f 78 78 78 20 2d 68 20 2d 73 20 73 73 6f 63 6b 73 64 } //01 00 
		$a_00_2 = {2e 2f 65 77 20 2d 73 20 6c 63 78 5f 6c 69 73 74 65 6e 20 2d 6c 20 31 30 38 30 20 2d 65 20 38 38 38 38 } //00 00 
	condition:
		any of ($a_*)
 
}
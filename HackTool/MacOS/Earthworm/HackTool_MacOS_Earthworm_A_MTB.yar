
rule HackTool_MacOS_Earthworm_A_MTB{
	meta:
		description = "HackTool:MacOS/Earthworm.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 72 6f 6f 74 6b 69 74 65 72 2e 63 6f 6d 2f 45 61 72 74 68 57 6f 72 6d 2f } //01 00 
		$a_00_1 = {2e 2f 78 78 78 20 2d 63 20 5b 72 68 6f 73 74 5d 20 2d 70 20 5b 72 70 6f 72 74 5d } //01 00 
		$a_00_2 = {2e 2f 61 67 65 6e 74 5f 65 78 65 20 2d 6c 20 38 38 38 38 } //00 00 
	condition:
		any of ($a_*)
 
}
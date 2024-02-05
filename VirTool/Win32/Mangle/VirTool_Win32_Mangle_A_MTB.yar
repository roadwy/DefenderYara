
rule VirTool_Win32_Mangle_A_MTB{
	meta:
		description = "VirTool:Win32/Mangle.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 69 6e 6a 65 63 74 2f 64 65 62 75 67 2f 70 65 2f 72 65 6c 6f 63 2e 67 6f } //01 00 
		$a_81_1 = {42 69 6e 6a 65 63 74 2f 64 65 62 75 67 2f 70 65 2e 28 2a 7a 65 72 6f 52 65 61 64 65 72 41 74 29 2e 52 65 61 64 41 74 } //01 00 
		$a_81_2 = {2f 4d 61 6e 67 6c 65 2f 4d 61 6e 67 6c 65 2e 67 6f } //00 00 
	condition:
		any of ($a_*)
 
}
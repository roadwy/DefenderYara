
rule VirTool_Win32_PPLdump_B_MTB{
	meta:
		description = "VirTool:Win32/PPLdump.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 69 6d 69 6b 61 74 7a 2e 65 78 65 20 22 73 65 6b 75 72 6c 73 61 3a 3a 6d 69 6e 69 64 75 6d 70 } //01 00 
		$a_81_1 = {5c 4b 6e 6f 77 6e 44 6c 6c 73 5c } //01 00 
		$a_01_2 = {70 79 70 79 6b 61 74 7a 20 6c 73 61 20 6d 69 6e 69 64 75 6d 70 } //00 00 
	condition:
		any of ($a_*)
 
}
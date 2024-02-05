
rule VirTool_Win32_Natoch_A_MTB{
	meta:
		description = "VirTool:Win32/Natoch.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {64 69 73 74 6f 72 6d 33 5c 64 69 73 74 6f 72 6d 33 2e 6e 69 6d } //01 00 
		$a_81_1 = {75 74 69 6c 73 5c 61 74 74 61 63 6b 73 2e 6e 69 6d } //01 00 
		$a_81_2 = {75 74 69 6c 73 5c 69 6e 73 70 65 63 74 2e 6e 69 6d } //01 00 
		$a_81_3 = {70 61 74 63 68 65 74 77 5f 63 6d 64 } //01 00 
		$a_81_4 = {45 74 77 45 76 65 6e 74 57 72 69 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}
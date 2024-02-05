
rule VirTool_Win32_Discratz_A_MTB{
	meta:
		description = "VirTool:Win32/Discratz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 62 77 6d 61 72 72 69 6e 2f 64 69 73 63 6f 72 64 67 6f } //01 00 
		$a_81_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 63 6f 64 65 75 6b 2f 64 69 73 63 6f 72 64 2d 72 61 74 } //01 00 
		$a_81_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f 67 6f 72 69 6c 6c 61 2f 77 65 62 73 6f 63 6b 65 74 } //01 00 
		$a_81_3 = {61 70 69 2e 69 70 69 66 79 2e 6f 72 67 } //01 00 
		$a_81_4 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d } //01 00 
		$a_81_5 = {6f 73 2f 65 78 65 63 } //00 00 
	condition:
		any of ($a_*)
 
}
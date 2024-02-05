
rule VirTool_Win32_Shrub_A_MTB{
	meta:
		description = "VirTool:Win32/Shrub.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6f 72 73 68 2f 69 6e 74 65 72 6e 61 6c 2f 73 73 68 6f 63 6b 73 } //01 00 
		$a_01_1 = {66 6c 61 74 74 65 6e 66 6c 6f 61 74 33 32 66 6c 6f 61 74 36 34 67 63 74 72 61 63 65 67 6f 72 73 68 } //01 00 
		$a_01_2 = {67 6f 72 73 68 2e 63 32 } //01 00 
		$a_01_3 = {48 6f 6c 65 79 53 6f 63 6b 73 2f 70 6b 67 2f 68 6f 6c 65 79 73 6f 63 6b 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Shrub_A_MTB_2{
	meta:
		description = "VirTool:Win32/Shrub.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6f 72 73 68 2f 69 6e 74 65 72 6e 61 6c 2f 63 6d 64 73 } //01 00 
		$a_01_1 = {67 6f 72 73 68 2f 69 6e 74 65 72 6e 61 6c 2f 65 6e 75 6d } //01 00 
		$a_01_2 = {67 6f 72 73 68 2f 69 6e 74 65 72 6e 61 6c 2f 6d 79 63 6f 6e 6e } //01 00 
		$a_01_3 = {67 6f 72 73 68 2f 69 6e 74 65 72 6e 61 6c 2f 66 65 74 63 68 2e 5f 64 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00 
		$a_01_4 = {67 6f 72 73 68 2f 69 6e 74 65 72 6e 61 6c 2f 65 6e 75 6d 2e 53 68 65 72 6c 6f 63 6b } //01 00 
		$a_01_5 = {61 75 64 69 62 6c 65 62 6c 69 6e 6b 2f 67 6f 72 73 68 2f 69 6e 74 65 72 6e 61 6c 2f 65 6e 75 6d 2e 57 69 6e 50 65 61 73 } //00 00 
	condition:
		any of ($a_*)
 
}
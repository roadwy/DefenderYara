
rule VirTool_Win32_PhycheStoic_A_MTB{
	meta:
		description = "VirTool:Win32/PhycheStoic.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6e 65 75 6d 61 2f 63 6f 6d 6d 61 6e 64 73 2e 65 78 65 63 75 74 65 } //01 00 
		$a_01_1 = {70 6e 65 75 6d 61 2f 63 6f 6d 6d 61 6e 64 73 2e 67 65 74 53 68 65 6c 6c 43 6f 6d 6d 61 6e 64 } //01 00 
		$a_01_2 = {62 65 61 63 6f 6e 2e 28 2a 42 65 61 63 6f 6e 49 6e 63 6f 6d 69 6e 67 29 2e 47 65 74 42 65 61 63 6f 6e } //01 00 
		$a_01_3 = {62 65 61 63 6f 6e 2e 28 2a 62 65 61 63 6f 6e 43 6c 69 65 6e 74 29 2e 48 61 6e 64 6c 65 } //01 00 
		$a_01_4 = {28 2a 41 67 65 6e 74 43 6f 6e 66 69 67 29 2e 42 75 69 6c 64 42 65 61 63 6f 6e } //01 00 
		$a_01_5 = {28 2a 41 67 65 6e 74 43 6f 6e 66 69 67 29 2e 42 75 69 6c 64 53 6f 63 6b 65 74 42 65 61 63 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
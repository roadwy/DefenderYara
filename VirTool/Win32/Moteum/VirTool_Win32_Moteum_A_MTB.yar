
rule VirTool_Win32_Moteum_A_MTB{
	meta:
		description = "VirTool:Win32/Moteum.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 65 78 2e 53 65 6e 64 46 69 6c 65 } //01 00 
		$a_01_1 = {70 6f 73 74 65 78 2e 52 65 63 76 46 69 6c 65 } //01 00 
		$a_01_2 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 } //01 00 
		$a_01_3 = {73 79 73 63 61 6c 6c 2f 77 69 6e 64 6f 77 73 2f 7a 73 79 73 63 61 6c 6c 5f 77 69 6e 64 6f 77 73 2e 67 6f } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Moteum_A_MTB_2{
	meta:
		description = "VirTool:Win32/Moteum.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 65 78 2e 53 74 61 72 74 53 4f 43 4b 53 50 72 6f 78 79 } //01 00 
		$a_01_1 = {70 6f 73 74 65 78 2e 68 61 6e 64 6c 65 53 4f 43 4b 53 } //01 00 
		$a_01_2 = {70 6f 73 74 65 78 2e 68 61 6e 64 6c 65 53 4f 43 4b 53 43 6f 6e 6e 65 63 74 69 6f 6e } //01 00 
		$a_01_3 = {70 6f 73 74 65 78 2e 68 61 6e 64 6c 65 53 4f 43 4b 53 43 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Moteum_A_MTB_3{
	meta:
		description = "VirTool:Win32/Moteum.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 65 78 2e 43 68 65 63 6b 53 68 65 6c 6c } //01 00 
		$a_01_1 = {70 6f 73 74 65 78 2e 64 6f 47 65 74 } //01 00 
		$a_01_2 = {70 6f 73 74 65 78 2e 52 65 76 65 72 73 65 54 43 50 53 68 65 6c 6c } //01 00 
		$a_01_3 = {70 6f 73 74 65 78 2e 52 65 76 65 72 73 65 55 44 50 53 68 65 6c 6c } //01 00 
		$a_01_4 = {70 6f 73 74 65 78 2e 52 65 76 65 72 73 65 53 68 65 6c 6c 48 54 54 50 53 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Moteum_A_MTB_4{
	meta:
		description = "VirTool:Win32/Moteum.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 65 78 2e 58 6f 72 69 66 79 } //01 00 
		$a_01_1 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 2f 73 72 63 2f 78 6f 72 74 6f 6f 6c 2f 78 6f 72 74 6f 6f 6c 2e 67 6f } //01 00 
		$a_01_2 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 2f 73 72 63 2f 70 6f 73 74 65 78 2f 78 6f 72 2e 67 6f } //01 00 
		$a_01_3 = {68 74 74 70 2f 73 6f 63 6b 73 5f 62 75 6e 64 6c 65 2e 67 6f } //01 00 
		$a_01_4 = {70 6f 73 74 65 78 2f 78 6f 72 2e 67 6f } //01 00 
		$a_01_5 = {74 6f 6f 6c 73 2f 78 6f 72 74 6f 6f 6c 2e 67 6f } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Moteum_A_MTB_5{
	meta:
		description = "VirTool:Win32/Moteum.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 65 78 2e 53 68 65 6c 6c 63 6f 64 65 57 69 6e 64 6f 77 73 } //01 00 
		$a_01_1 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 2f 73 72 63 2f 73 68 65 6c 6c 63 6f 64 65 2f 73 68 65 6c 6c 63 6f 64 65 2d 77 69 6e 64 6f 77 73 2e 67 6f } //01 00 
		$a_01_2 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 2f 73 72 63 2f 70 6f 73 74 65 78 2f 73 68 65 6c 6c 63 6f 64 65 2d 77 69 6e 2e 67 6f } //01 00 
		$a_01_3 = {73 79 73 63 61 6c 6c 2f 77 69 6e 64 6f 77 73 2f 7a 73 79 73 63 61 6c 6c 5f 77 69 6e 64 6f 77 73 2e 67 6f } //01 00 
		$a_01_4 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 2f 70 6f 73 74 65 78 2f 73 68 65 6c 6c 63 6f 64 65 2d 77 69 6e 2e 67 6f } //01 00 
		$a_01_5 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 2f 74 6f 6f 6c 73 2f 73 68 65 6c 6c 63 6f 64 65 2d 77 69 6e 64 6f 77 73 2e 67 6f } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Moteum_A_MTB_6{
	meta:
		description = "VirTool:Win32/Moteum.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 65 78 2e 53 68 65 6c 6c 63 6f 64 65 49 6e 6a 65 63 74 57 69 6e 64 6f 77 73 } //01 00 
		$a_01_1 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 2f 73 72 63 2f 73 68 65 6c 6c 63 6f 64 65 2d 69 6e 6a 65 63 74 2f 73 68 65 6c 6c 63 6f 64 65 2d 69 6e 6a 65 63 74 2d 77 69 6e 64 6f 77 73 2e 67 6f } //01 00 
		$a_01_2 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 2f 73 72 63 2f 70 6f 73 74 65 78 2f 73 68 65 6c 6c 63 6f 64 65 2d 77 69 6e 2e 67 6f } //01 00 
		$a_01_3 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 2f 70 6f 73 74 65 78 2f 73 68 65 6c 6c 63 6f 64 65 2d 77 69 6e 2e 67 6f } //01 00 
		$a_01_4 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 2f 74 6f 6f 6c 73 2f 73 68 65 6c 6c 63 6f 64 65 2d 69 6e 6a 65 63 74 2d 77 69 6e 64 6f 77 73 2e 67 6f } //01 00 
		$a_01_5 = {2f 6e 65 74 2f 68 74 74 70 2f 68 74 74 70 70 72 6f 78 79 2f 70 72 6f 78 79 2e 67 6f } //00 00 
	condition:
		any of ($a_*)
 
}

rule VirTool_Win64_Nitematz_B_MTB{
	meta:
		description = "VirTool:Win64/Nitematz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 5c 3f 5c 47 4c 4f 42 41 4c 52 4f 4f 54 5c 44 65 76 69 63 65 5c 48 61 72 64 64 69 73 6b 56 6f 6c 75 6d 65 53 68 61 64 6f 77 43 6f 70 79 } //1 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy
		$a_81_1 = {57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6f 6e 66 69 67 5c 53 41 4d } //1 Windows\System32\config\SAM
		$a_81_2 = {57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6f 6e 66 69 67 5c 53 45 43 55 52 49 54 59 } //1 Windows\System32\config\SECURITY
		$a_81_3 = {57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6f 6e 66 69 67 5c 53 59 53 54 45 4d } //1 Windows\System32\config\SYSTEM
		$a_03_4 = {48 89 6c 24 30 48 8d 90 01 06 c7 44 24 28 90 01 01 00 00 00 45 33 c9 45 33 c0 c7 44 24 20 03 00 00 00 ba 00 00 00 80 ff 15 90 01 04 48 83 f8 ff 75 0d ff c3 3b df 90 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
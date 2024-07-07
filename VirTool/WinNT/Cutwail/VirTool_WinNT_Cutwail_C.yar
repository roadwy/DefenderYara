
rule VirTool_WinNT_Cutwail_C{
	meta:
		description = "VirTool:WinNT/Cutwail.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 18 3d 28 0a 00 00 74 07 3d ce 0e 00 00 75 40 c6 45 ff bf c6 45 fe 57 eb 08 c6 45 ff ba c6 45 fe 84 60 b8 } //2
		$a_01_1 = {81 f9 93 08 00 00 b8 f8 00 00 00 74 1a 81 f9 28 0a 00 00 74 0d 81 f9 ce 0e 00 } //2
		$a_03_2 = {fa 0f 20 c0 89 45 90 01 01 25 ff ff fe ff 0f 22 c0 90 00 } //2
		$a_01_3 = {66 81 3e 4d 5a 75 0d 8b 46 3c 03 c6 66 81 78 14 e0 00 } //1
		$a_00_4 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 ZwQuerySystemInformation
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
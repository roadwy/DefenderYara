
rule VirTool_WinNT_Rootkitdrv_AR{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.AR,SIGNATURE_TYPE_PEHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 64 00 "
		
	strings :
		$a_02_0 = {83 26 00 83 66 04 00 2d 90 01 04 74 56 83 e8 04 74 0b c7 06 10 00 00 c0 90 00 } //0a 00 
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4e 00 65 00 73 00 73 00 65 00 72 00 79 00 } //0a 00 
		$a_00_2 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 4e 00 65 00 73 00 73 00 65 00 72 00 79 00 } //0a 00 
		$a_00_3 = {5c 53 79 73 5c 65 78 65 5c 69 33 38 36 5c 6d 73 64 69 72 65 63 74 78 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}
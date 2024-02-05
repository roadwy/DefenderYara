
rule VirTool_WinNT_Oanum_sys{
	meta:
		description = "VirTool:WinNT/Oanum!sys,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {0f 20 c0 89 45 e0 25 ff ff fe ff 0f 22 c0 fa } //02 00 
		$a_00_1 = {83 7d fc 2b 72 be fb 8b } //02 00 
		$a_00_2 = {fb 8b 45 e0 0f 22 c0 6a 01 } //02 00 
		$a_00_3 = {66 65 72 65 73 79 73 } //01 00 
		$a_01_4 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00 
		$a_00_5 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
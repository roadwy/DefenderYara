
rule VirTool_WinNT_Rootkitdrv_AS{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.AS,SIGNATURE_TYPE_PEHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 64 00 "
		
	strings :
		$a_02_0 = {c7 45 fc 00 00 00 00 eb 90 01 01 8b 45 fc 83 c0 01 89 45 fc 81 7d fc 00 10 00 00 73 90 01 01 6a 06 8b 4d 08 03 4d fc 51 68 90 00 } //0a 00 
		$a_00_1 = {5c 4a 43 43 5f 57 4f 52 4b 5c 43 75 72 72 65 6e 74 57 6f 72 6b 69 6e 67 5c 72 6f 6f 74 6b 69 74 5c 70 68 76 78 64 5c 52 65 6c 65 61 73 65 5c 70 68 76 78 64 2e 70 64 62 } //0a 00 
		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 70 00 68 00 76 00 78 00 64 00 } //0a 00 
		$a_00_3 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 70 00 68 00 76 00 78 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule VirTool_WinNT_Rootkitdrv_GY{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {50 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 58 } //02 00 
		$a_03_1 = {8b 50 01 8b 31 8b 14 96 89 15 90 01 02 01 00 8b 40 01 8b 09 c7 04 81 90 01 02 01 00 50 8b 44 24 08 0f 22 c0 90 00 } //01 00 
		$a_01_2 = {5a 77 51 75 65 72 79 44 69 72 65 63 74 6f 72 79 46 69 6c 65 } //00 00  ZwQueryDirectoryFile
	condition:
		any of ($a_*)
 
}
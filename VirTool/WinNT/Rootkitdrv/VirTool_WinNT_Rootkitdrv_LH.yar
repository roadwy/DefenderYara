
rule VirTool_WinNT_Rootkitdrv_LH{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 64 44 69 73 61 62 6c 65 44 65 62 75 67 67 65 72 } //01 00 
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 44 00 69 00 73 00 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 25 00 64 00 } //01 00 
		$a_03_2 = {83 e8 24 c6 00 0d 8b 8d 90 01 02 ff ff 8b 49 08 8b 49 08 89 48 14 8b 8d 90 01 02 ff ff 89 48 18 8d 8d 90 01 02 ff ff c7 40 0c 73 00 09 00 c7 40 08 08 00 00 00 89 48 10 c7 40 04 10 01 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule VirTool_WinNT_Rootkitdrv_HQ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.HQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 3f 00 3f 00 5c 00 54 00 58 00 51 00 51 00 } //01 00  \??\TXQQ
		$a_00_1 = {49 00 6d 00 61 00 67 00 65 00 20 00 46 00 69 00 6c 00 65 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 20 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 } //01 00  Image File Execution Options
		$a_03_2 = {8b 48 60 83 e9 24 89 4d 90 01 01 8b 55 90 01 01 c7 42 1c 90 01 04 8b 45 90 00 } //01 00 
		$a_03_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 45 90 01 01 8b 4d 90 01 01 8b 55 90 01 01 8b 12 89 14 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
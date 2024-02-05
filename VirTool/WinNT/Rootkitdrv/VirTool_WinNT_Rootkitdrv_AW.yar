
rule VirTool_WinNT_Rootkitdrv_AW{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.AW,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 53 00 79 00 73 00 44 00 72 00 76 00 65 00 72 00 } //0a 00 
		$a_00_1 = {5c 6f 62 6a 66 72 65 5f 77 6e 65 74 5f 78 38 36 5c 69 33 38 36 5c 53 79 73 44 72 76 65 72 2e 70 64 62 } //01 00 
		$a_00_2 = {89 14 81 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //01 00 
		$a_02_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 83 3d 90 01 03 00 00 8b 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
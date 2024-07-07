
rule VirTool_WinNT_Rootkitdrv_GI{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 f9 10 24 08 00 0f 90 01 02 00 00 00 81 f9 08 20 22 00 0f 90 01 02 00 00 00 81 f9 17 e4 22 00 0f 90 01 02 00 00 00 90 00 } //1
		$a_03_1 = {03 00 12 00 89 45 90 01 01 0f 85 90 01 02 00 00 85 c0 0f 8c 90 01 02 00 00 57 6a 05 59 8d 7d 90 01 01 f3 a5 81 7d 90 01 01 00 04 00 00 0f 85 28 01 00 00 83 7d 90 01 01 00 0f 85 90 01 02 00 00 81 7d 90 01 01 00 02 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
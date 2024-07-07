
rule VirTool_WinNT_Rootkitdrv_KV{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 06 8d 04 3e 50 68 90 01 04 ff 15 90 01 04 83 c4 0c 85 c0 75 90 01 01 89 35 90 01 04 46 81 fe 00 30 00 00 7c 90 00 } //1
		$a_03_1 = {8b 00 25 ff ff 00 00 2d 21 04 00 00 74 90 14 c7 05 90 01 04 1e 00 00 00 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
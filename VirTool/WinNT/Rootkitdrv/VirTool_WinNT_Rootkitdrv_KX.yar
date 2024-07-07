
rule VirTool_WinNT_Rootkitdrv_KX{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 7d 24 01 74 90 01 01 83 7d 24 02 74 90 01 01 83 7d 24 26 74 90 01 01 83 7d 24 03 74 90 01 01 83 7d 24 25 74 90 01 01 83 7d 24 0c 0f 85 90 00 } //1
		$a_03_1 = {83 39 00 74 90 01 01 8b 55 90 01 01 8b 45 0c 03 02 89 45 0c eb 07 c7 45 0c 00 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
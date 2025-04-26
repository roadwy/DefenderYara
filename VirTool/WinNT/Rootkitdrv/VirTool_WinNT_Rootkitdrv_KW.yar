
rule VirTool_WinNT_Rootkitdrv_KW{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 3e 0e 0f 85 ?? ?? ?? ?? 81 7e 0c 04 20 22 00 0f 85 } //1
		$a_01_1 = {3b 5d 1c 75 09 c7 45 2c 06 00 00 80 eb 06 8b 45 30 83 20 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
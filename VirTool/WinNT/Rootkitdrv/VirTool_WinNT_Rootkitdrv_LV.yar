
rule VirTool_WinNT_Rootkitdrv_LV{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 50 5f 50 52 4f 54 45 43 54 49 4f 4e } //1 DP_PROTECTION
		$a_03_1 = {ff 75 08 e8 ?? ?? ff ff 84 c0 74 0b b8 0f 00 00 c0 83 4d fc ff eb } //1
		$a_03_2 = {83 7d e4 00 0f 85 ?? ?? 00 00 83 7d 24 03 0f 85 ?? ?? 00 00 8b fb 89 7d dc 83 65 e0 00 85 ff 0f 84 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
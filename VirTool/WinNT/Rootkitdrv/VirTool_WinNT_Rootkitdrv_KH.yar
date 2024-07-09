
rule VirTool_WinNT_Rootkitdrv_KH{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 6d f4 04 00 61 25 74 ?? 83 6d f4 04 74 } //1
		$a_03_1 = {50 33 c0 33 c0 33 c0 33 c0 33 c0 33 c0 90 13 58 } //1
		$a_03_2 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 a1 ?? ?? ?? ?? 8b 40 01 8b 0d ?? ?? ?? ?? 8b 09 c7 04 81 ?? ?? ?? ?? 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
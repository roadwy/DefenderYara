
rule VirTool_WinNT_Rootkitdrv_LC{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c0 89 45 18 76 ?? 89 75 20 eb 03 8b ?? 1c 8b ?? be 6a 00 ?? ff 15 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 85 c0 74 0c 8b 45 1c 83 ?? b8 00 ff 4d 18 } //1
		$a_03_1 = {8b 40 10 c1 e1 02 85 f6 8b 14 01 75 03 33 c0 c3 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 a1 ?? ?? ?? ?? 8b 40 10 89 34 01 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
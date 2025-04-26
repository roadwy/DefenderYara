
rule VirTool_WinNT_Rootkitdrv_HQ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.HQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 00 3f 00 3f 00 5c 00 54 00 58 00 51 00 51 00 } //1 \??\TXQQ
		$a_00_1 = {49 00 6d 00 61 00 67 00 65 00 20 00 46 00 69 00 6c 00 65 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 20 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 } //1 Image File Execution Options
		$a_03_2 = {8b 48 60 83 e9 24 89 4d ?? 8b 55 ?? c7 42 1c ?? ?? ?? ?? 8b 45 } //1
		$a_03_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 45 ?? 8b 4d ?? 8b 55 ?? 8b 12 89 14 81 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
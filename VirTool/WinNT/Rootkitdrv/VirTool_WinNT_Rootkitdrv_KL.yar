
rule VirTool_WinNT_Rootkitdrv_KL{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 66 81 38 4d 5a 0f 85 ?? 00 00 00 8b 50 3c 03 55 08 81 3a 50 45 00 00 0f 85 9c 00 00 00 8b 42 34 89 45 ?? 8b 82 a0 00 00 00 8b 92 a4 00 00 00 } //1
		$a_03_1 = {fa 50 0f 20 c0 89 45 ?? 25 ff ff fe ff 0f 22 c0 58 52 8b c6 c1 e0 02 03 45 ?? 50 e8 ?? 00 00 00 50 8b 45 ?? 0f 22 c0 58 fb } //1
		$a_03_2 = {8b 40 3c 03 c3 89 45 ?? 8b 45 ?? 81 38 50 45 00 00 74 ?? 53 e8 ?? ?? 00 00 e9 ?? 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}

rule VirTool_WinNT_Rootkitdrv_KG{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 52 00 45 00 53 00 53 00 44 00 54 00 } //1 \Device\RESSDT
		$a_03_1 = {81 fa c0 20 22 00 0f 84 ?? 00 00 00 81 fa 4b e1 22 00 0f 85 ?? 00 00 00 } //1
		$a_01_2 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 07 89 04 b1 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
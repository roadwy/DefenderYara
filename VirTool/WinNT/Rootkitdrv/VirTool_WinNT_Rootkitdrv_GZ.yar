
rule VirTool_WinNT_Rootkitdrv_GZ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 64 00 61 00 71 00 64 00 72 00 76 00 00 00 } //1
		$a_01_1 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 00 } //1
		$a_01_2 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 45 e4 8b 00 89 04 9f 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 33 ff eb 1b 8b 45 ec 8b 00 8b 00 89 45 dc 33 c0 40 c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule VirTool_WinNT_Rootkitdrv_I{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 45 e4 8b c0 81 f9 4b e1 22 00 74 0a 90 01 01 bb 00 00 c0 e9 90 01 02 00 00 83 65 fc 00 6a 04 6a 04 53 ff 15 90 00 } //1
		$a_03_1 = {39 48 08 77 07 90 01 01 0d 00 00 c0 eb 90 01 01 8b 00 8b 14 88 8b 90 01 01 8b 90 01 03 01 00 3b 90 01 01 01 75 90 00 } //1
		$a_01_2 = {c6 45 dc e9 2b c2 83 e8 05 89 45 dd 6a 05 52 8d 45 dc 50 e8 } //1
		$a_01_3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}

rule VirTool_WinNT_Rootkitdrv_BS{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.BS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 00 89 45 c8 ff 36 53 68 90 01 04 e8 90 01 02 00 00 83 c4 0c fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 8b 4d c8 89 04 99 0f 20 c0 0d 00 00 01 00 0f 22 c0 90 00 } //1
		$a_02_1 = {83 65 fc 00 6a 04 6a 04 53 ff 15 90 01 04 6a 04 6a 04 56 ff 15 90 01 04 83 4d fc ff 8b 1b a1 90 01 04 39 58 08 77 09 c7 45 d0 0d 00 00 c0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
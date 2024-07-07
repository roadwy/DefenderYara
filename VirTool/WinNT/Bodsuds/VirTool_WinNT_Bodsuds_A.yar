
rule VirTool_WinNT_Bodsuds_A{
	meta:
		description = "VirTool:WinNT/Bodsuds.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 f9 32 7c e8 eb b7 83 c0 05 8b 08 8d 4c 01 04 81 79 01 ff 55 8b ec 89 4c 24 04 74 19 } //1
		$a_01_1 = {83 fa 30 7c e8 eb e0 83 c0 05 8b 10 8d 54 02 04 } //1
		$a_01_2 = {bf 10 00 00 c0 74 4f 81 f9 4b e1 22 00 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
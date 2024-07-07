
rule VirTool_WinNT_Laqma_C{
	meta:
		description = "VirTool:WinNT/Laqma.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b7 00 3d 93 08 00 00 74 90 01 01 3d 28 0a 00 00 74 90 01 01 3d ce 0e 00 00 74 90 00 } //2
		$a_01_1 = {fa 0f 20 c0 89 44 24 00 25 ff ff fe ff 0f 22 c0 a1 } //2
		$a_01_2 = {8b 44 24 00 0f 22 c0 fb b0 01 59 c3 } //2
		$a_01_3 = {eb 08 66 83 38 5c 74 0c 48 48 3b c7 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=5
 
}

rule VirTool_WinNT_Boaxxe_A{
	meta:
		description = "VirTool:WinNT/Boaxxe.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 "
		
	strings :
		$a_02_0 = {3b c6 0f 8c 90 01 01 02 00 00 8b 85 90 01 02 ff ff 8b 15 90 01 02 01 00 8b 0d 90 01 02 01 00 89 85 90 01 02 ff ff 89 85 90 01 02 ff ff a1 90 00 } //2
		$a_02_1 = {89 85 94 fa ff ff 75 07 33 c0 e9 90 01 01 03 00 00 33 c0 6a 32 b9 00 01 00 00 8d bd 9c fa ff ff f3 ab 59 6a 90 00 } //2
		$a_01_2 = {42 00 6f 00 6f 00 74 00 20 00 42 00 75 00 73 00 20 00 45 00 78 00 74 00 65 00 6e 00 64 00 65 00 72 00 } //1 Boot Bus Extender
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}
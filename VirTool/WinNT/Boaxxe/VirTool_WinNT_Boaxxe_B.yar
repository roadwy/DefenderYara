
rule VirTool_WinNT_Boaxxe_B{
	meta:
		description = "VirTool:WinNT/Boaxxe.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 "
		
	strings :
		$a_02_0 = {3b c6 0f 8c ?? (02|03) 00 00 8b 85 ?? ?? ff ff 89 85 ?? ?? ff ff 89 85 ?? ?? ff ff a1 } //2
		$a_02_1 = {33 c0 8d bd (84|94) fa ff ff f3 ab 6a 32 59 8d bd (84|94) fe ff ff f3 ab 6a (|) 54 5b 59 8d bd (|) f0 fc f4 ff ff f3 ab 0f b7 8d (|) 5c 6c f6 ff ff } //2
		$a_01_2 = {42 00 6f 00 6f 00 74 00 20 00 42 00 75 00 73 00 20 00 45 00 78 00 74 00 65 00 6e 00 64 00 65 00 72 00 } //1 Boot Bus Extender
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}
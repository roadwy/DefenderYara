
rule VirTool_WinNT_Boaxxe_B{
	meta:
		description = "VirTool:WinNT/Boaxxe.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {3b c6 0f 8c 90 01 01 90 03 01 01 02 03 00 00 8b 85 90 01 02 ff ff 89 85 90 01 02 ff ff 89 85 90 01 02 ff ff a1 90 00 } //02 00 
		$a_02_1 = {33 c0 8d bd 90 03 01 01 84 94 fa ff ff f3 ab 6a 32 59 8d bd 90 03 01 01 84 94 fe ff ff f3 ab 6a 90 03 01 01 54 5b 59 8d bd 90 03 01 01 f0 fc f4 ff ff f3 ab 0f b7 8d 90 03 01 01 5c 6c f6 ff ff 90 00 } //01 00 
		$a_01_2 = {42 00 6f 00 6f 00 74 00 20 00 42 00 75 00 73 00 20 00 45 00 78 00 74 00 65 00 6e 00 64 00 65 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}
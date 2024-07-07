
rule VirTool_Win32_Obfuscator_WM{
	meta:
		description = "VirTool:Win32/Obfuscator.WM,SIGNATURE_TYPE_PEHSTR_EXT,64 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 68 60 d0 09 01 6a 00 6a 00 6a 00 e8 90 01 04 83 ec 08 e8 90 01 04 e8 90 01 04 8b 48 3b 8d 04 08 83 c0 28 8b 00 60 b4 20 2a c4 0f 8f 90 01 04 61 c3 90 00 } //5
		$a_03_1 = {64 66 8b ff 8d 90 01 03 00 00 33 c0 ff b0 90 01 04 c2 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}
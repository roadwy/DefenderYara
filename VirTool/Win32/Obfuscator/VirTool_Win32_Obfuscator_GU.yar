
rule VirTool_Win32_Obfuscator_GU{
	meta:
		description = "VirTool:Win32/Obfuscator.GU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 83 f8 58 90 02 20 0f b6 40 ff 83 f8 50 90 02 20 0f b6 40 fe 83 f8 55 90 00 } //2
		$a_01_1 = {68 00 40 00 00 68 00 04 00 00 6a 01 ff 15 } //1
		$a_03_2 = {68 00 08 00 00 6a 08 ff 75 90 01 01 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
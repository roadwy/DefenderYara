
rule VirTool_Win32_Obfuscator_ABS{
	meta:
		description = "VirTool:Win32/Obfuscator.ABS,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4d 10 83 f9 00 75 02 eb 90 01 01 eb 09 8b 4d 90 01 01 03 4d 90 01 01 89 4d 90 01 01 8b 4d 90 01 01 3b 4d 0c 73 90 01 01 8a 4d 10 90 00 } //1
		$a_03_1 = {3b 4d f7 76 02 eb 90 01 01 8b 4d 08 03 4d fc 8a 45 fb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
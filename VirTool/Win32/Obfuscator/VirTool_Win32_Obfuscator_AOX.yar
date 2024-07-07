
rule VirTool_Win32_Obfuscator_AOX{
	meta:
		description = "VirTool:Win32/Obfuscator.AOX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be 02 33 c8 8b 15 90 01 04 03 15 90 01 04 88 0a 90 00 } //2
		$a_03_1 = {6a 00 6a 00 6a 00 90 02 10 6a 00 6a 00 6a 00 6a 00 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
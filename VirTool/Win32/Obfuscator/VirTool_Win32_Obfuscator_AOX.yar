
rule VirTool_Win32_Obfuscator_AOX{
	meta:
		description = "VirTool:Win32/Obfuscator.AOX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be 02 33 c8 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 88 0a } //2
		$a_03_1 = {6a 00 6a 00 6a 00 [0-10] 6a 00 6a 00 6a 00 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}

rule VirTool_Win32_Obfuscator_WO{
	meta:
		description = "VirTool:Win32/Obfuscator.WO,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {52 75 6e 00 ?? ?? ?? ?? ?? ?? ?? ?? 33 31 34 32 } //1
		$a_03_1 = {33 31 34 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 52 75 6e } //1
		$a_00_2 = {29 18 68 fc e3 fe f8 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*10) >=11
 
}
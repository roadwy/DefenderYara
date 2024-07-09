
rule VirTool_Win32_Obfuscator_DW{
	meta:
		description = "VirTool:Win32/Obfuscator.DW,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 de 81 c8 ?? ?? ?? ?? 8b 4e 2c 53 48 66 33 c9 c1 f8 1d 51 90 90 29 c0 8b 15 ?? ?? ?? ?? 41 ff d2 } //1
		$a_02_1 = {ff d2 59 ba ?? ?? ?? ?? f7 d2 8b 3a f7 d0 4a 41 21 d6 8b 01 81 ea a5 6a cd 83 31 f8 85 c0 75 ee } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}

rule VirTool_Win32_Obfuscator_ZY{
	meta:
		description = "VirTool:Win32/Obfuscator.ZY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 fa 22 67 3f 7a 74 90 01 01 81 fa 67 22 7a 3f 0f 84 90 01 04 81 fa 30 75 2d 68 90 00 } //1
		$a_01_1 = {0f a2 31 d8 3d 46 65 6e 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
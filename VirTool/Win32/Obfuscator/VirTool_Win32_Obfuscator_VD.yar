
rule VirTool_Win32_Obfuscator_VD{
	meta:
		description = "VirTool:Win32/Obfuscator.VD,SIGNATURE_TYPE_PEHSTR_EXT,64 00 14 00 02 00 00 "
		
	strings :
		$a_13_0 = {0f 68 19 2b 90 90 95 ff 75 e0 e8 90 01 02 ff ff ff 90 00 0a } //10
		$a_68_1 = {80 ac c8 ff 75 e0 e8 90 01 02 ff ff 59 59 8b 4d d8 89 41 } //9728
	condition:
		((#a_13_0  & 1)*10+(#a_68_1  & 1)*9728) >=20
 
}
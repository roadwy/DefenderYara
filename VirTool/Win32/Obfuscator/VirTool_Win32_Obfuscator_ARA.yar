
rule VirTool_Win32_Obfuscator_ARA{
	meta:
		description = "VirTool:Win32/Obfuscator.ARA,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 ff 30 58 31 d8 83 eb ff 3d } //1
		$a_01_1 = {66 b8 00 00 66 bb 4d 5a 66 39 18 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
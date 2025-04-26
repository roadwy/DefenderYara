
rule VirTool_Win32_Obfuscator_ZI{
	meta:
		description = "VirTool:Win32/Obfuscator.ZI,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {a0 40 00 81 05 f4 ac 40 00 00 c0 00 00 8d ?? dc } //1
		$a_03_1 = {60 ae 0a 00 0f 82 ?? ff ff ff ff (15|35) f4 ac 40 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
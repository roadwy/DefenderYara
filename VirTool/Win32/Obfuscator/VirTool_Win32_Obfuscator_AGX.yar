
rule VirTool_Win32_Obfuscator_AGX{
	meta:
		description = "VirTool:Win32/Obfuscator.AGX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 c7 07 66 ad 83 f8 61 72 08 83 f8 7a 77 03 83 e0 df 81 c7 a0 af 0b 00 03 f8 49 0b c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
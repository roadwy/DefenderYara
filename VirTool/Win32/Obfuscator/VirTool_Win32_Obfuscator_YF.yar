
rule VirTool_Win32_Obfuscator_YF{
	meta:
		description = "VirTool:Win32/Obfuscator.YF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 50 78 85 c0 0f 85 94 00 00 00 8b 45 cc 8b 40 18 89 45 f4 8b 45 f4 8b 55 f8 89 42 40 3d 00 00 40 00 74 09 c7 42 2e 01 00 00 00 eb 07 c7 42 2e 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
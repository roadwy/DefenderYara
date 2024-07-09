
rule VirTool_Win32_Obfuscator_IO{
	meta:
		description = "VirTool:Win32/Obfuscator.IO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 f5 ff 00 00 01 f0 89 85 40 fd ff ff 89 85 c4 fd ff ff 89 ?? c7 85 d0 fd ff ff ?? 00 00 00 c7 85 d1 fd ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
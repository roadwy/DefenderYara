
rule VirTool_Win32_Obfuscator_RR{
	meta:
		description = "VirTool:Win32/Obfuscator.RR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 50 2e 89 48 39 8d 90 90 a7 02 00 00 8d 88 b6 02 00 00 89 50 44 89 48 4f c6 40 60 bf 8b 15 ?? ?? ?? ?? 89 50 61 c6 40 65 90 90 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
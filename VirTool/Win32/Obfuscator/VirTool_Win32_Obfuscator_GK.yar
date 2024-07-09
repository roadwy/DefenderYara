
rule VirTool_Win32_Obfuscator_GK{
	meta:
		description = "VirTool:Win32/Obfuscator.GK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 e8 01 ca 01 eb 89 d8 68 7c ea 00 00 ff 15 ?? ?? 41 00 68 8b 30 41 00 8d 14 30 8d 83 89 00 00 00 5a 8d 14 08 8d 04 10 68 06 b6 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
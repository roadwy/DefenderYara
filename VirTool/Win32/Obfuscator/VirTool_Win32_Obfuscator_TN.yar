
rule VirTool_Win32_Obfuscator_TN{
	meta:
		description = "VirTool:Win32/Obfuscator.TN,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {59 eb 00 5a 51 a1 ?? ?? ?? ?? eb 14 83 e0 fd 33 c1 05 bd 04 00 00 a3 ?? ?? ?? ?? c1 c8 10 eb 0c 8b c8 c1 e0 02 d1 c0 83 e0 fa eb e0 c1 c8 08 89 02 83 c2 04 c7 02 02 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
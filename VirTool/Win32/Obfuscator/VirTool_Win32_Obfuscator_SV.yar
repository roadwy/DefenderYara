
rule VirTool_Win32_Obfuscator_SV{
	meta:
		description = "VirTool:Win32/Obfuscator.SV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {d1 e8 eb 02 00 00 c1 e8 02 eb 02 00 00 c1 e8 04 05 81 11 10 00 ff e0 } //01 00 
		$a_01_1 = {e2 db e9 4b f6 ff ff 59 5e a1 a2 10 10 00 30 06 eb e3 } //00 00 
	condition:
		any of ($a_*)
 
}
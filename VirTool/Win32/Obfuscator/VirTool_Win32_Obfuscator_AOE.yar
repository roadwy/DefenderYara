
rule VirTool_Win32_Obfuscator_AOE{
	meta:
		description = "VirTool:Win32/Obfuscator.AOE,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 8b d8 56 53 51 8b 0f 8b 06 46 33 c8 8b c1 aa 59 4b 74 07 49 75 ee 5b 5e 5b c3 5b 2b f3 53 eb f3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule VirTool_Win32_Obfuscator_KA{
	meta:
		description = "VirTool:Win32/Obfuscator.KA,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_07_0 = {64 8b 15 18 00 00 00 90 02 20 8b 52 30 90 02 ff cd 2e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
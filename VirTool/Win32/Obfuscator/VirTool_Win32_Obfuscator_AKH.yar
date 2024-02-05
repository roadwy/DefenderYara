
rule VirTool_Win32_Obfuscator_AKH{
	meta:
		description = "VirTool:Win32/Obfuscator.AKH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 5c 3e 05 8d 74 3e 0a 8a 06 90 01 01 d3 32 d0 8b 45 f8 83 c6 02 88 94 05 c4 f3 ff ff 40 3d 90 01 04 89 45 f8 7e e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
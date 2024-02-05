
rule VirTool_Win32_Obfuscator_SD{
	meta:
		description = "VirTool:Win32/Obfuscator.SD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 ca 05 89 55 e4 ba 0d 0f 00 00 ff 4d 24 81 ea 4a 0f 00 00 } //01 00 
		$a_01_1 = {c1 eb 07 c1 e3 08 89 5d e4 bb e2 08 00 00 c1 cb 1d 81 c3 98 00 00 00 } //01 00 
		$a_01_2 = {c0 c8 19 c0 c0 0e 2c 08 c0 c0 15 c0 c8 02 } //00 00 
	condition:
		any of ($a_*)
 
}

rule VirTool_Win32_Obfuscator_MC{
	meta:
		description = "VirTool:Win32/Obfuscator.MC,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_10_0 = {64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 00 8b 40 08 } //01 00 
		$a_10_1 = {0f b7 03 8b f0 81 e6 00 f0 00 00 bf 00 30 00 00 66 3b f7 75 } //01 00 
		$a_10_2 = {25 ff 0f 00 00 03 01 03 45 08 01 10 8b 41 04 43 83 e8 08 43 ff 45 0c d1 e8 39 45 0c } //01 00 
		$a_12_3 = {4d fc 8b c1 99 83 e2 07 03 c2 8b 55 08 c1 f8 03 03 c2 81 e1 07 00 00 80 90 01 02 49 83 c9 f8 41 83 45 fc 05 d3 e6 09 30 43 3b 5d 10 90 00 00 } //00 87 
	condition:
		any of ($a_*)
 
}
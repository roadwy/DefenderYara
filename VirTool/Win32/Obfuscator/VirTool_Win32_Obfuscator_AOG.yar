
rule VirTool_Win32_Obfuscator_AOG{
	meta:
		description = "VirTool:Win32/Obfuscator.AOG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 0f 90 01 04 30 14 38 90 90 90 90 90 90 90 90 90 00 } //01 00 
		$a_03_1 = {6b 88 5c 24 90 01 01 c6 44 24 90 01 01 72 c6 44 24 90 01 01 6e 88 5c 24 90 01 01 c6 44 24 90 01 01 6c c6 44 24 90 01 01 33 c6 44 24 90 01 01 32 c6 44 24 90 01 01 2e c6 44 24 90 01 01 64 c6 44 24 90 01 01 6c c6 44 24 90 01 01 6c 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}
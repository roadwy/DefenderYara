
rule VirTool_Win32_Obfuscator_ALF{
	meta:
		description = "VirTool:Win32/Obfuscator.ALF,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {51 53 8b c1 56 c7 44 24 08 00 00 00 00 bb 90 01 04 8d 70 01 8a 10 83 c0 01 84 d2 75 f7 2b c6 8b f0 33 c0 85 f6 7e 0a 30 1c 08 83 c0 01 3b c6 7c f6 8b c1 c7 47 18 0f 00 00 00 c7 47 14 00 00 00 00 c6 47 04 00 8d 70 01 8d a4 24 00 00 00 00 8a 10 83 c0 01 84 d2 75 f7 2b c6 50 51 8b cf e8 1c fc ff ff 5e 8b c7 5b 59 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
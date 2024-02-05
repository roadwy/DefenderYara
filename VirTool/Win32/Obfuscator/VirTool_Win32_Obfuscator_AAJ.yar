
rule VirTool_Win32_Obfuscator_AAJ{
	meta:
		description = "VirTool:Win32/Obfuscator.AAJ,SIGNATURE_TYPE_PEHSTR,0a 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 10 0f b6 52 04 c1 e2 18 8b 4d 10 0f b6 49 05 c1 e1 10 31 ca 8b 4d 10 0f b6 49 06 } //01 00 
		$a_01_1 = {53 56 8b 44 24 0c 8b 54 24 10 8b 4c 24 14 0f b6 1a c1 e3 18 0f b6 72 01 c1 e6 10 31 f3 0f b6 72 02 c1 e6 08 31 f3 } //01 00 
		$a_01_2 = {8b 55 10 0f b6 12 c1 e2 18 8b 4d 10 0f b6 49 01 c1 e1 10 31 ca 8b 4d 10 0f b6 49 02 c1 e1 08 31 ca } //00 00 
	condition:
		any of ($a_*)
 
}
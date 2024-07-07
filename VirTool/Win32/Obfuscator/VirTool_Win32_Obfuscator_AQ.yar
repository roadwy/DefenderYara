
rule VirTool_Win32_Obfuscator_AQ{
	meta:
		description = "VirTool:Win32/Obfuscator.AQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 c3 00 00 01 00 81 fb 00 00 90 01 02 75 05 bb 00 00 90 01 02 e8 90 01 04 83 f9 00 74 de 8b cb 81 c1 00 00 90 01 02 66 81 39 4d 5a 75 cf 8b 41 3c 03 c1 8b 40 78 83 f8 00 74 c2 03 c1 8b 50 0c 03 d1 81 3a 4b 45 52 4e 75 b3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
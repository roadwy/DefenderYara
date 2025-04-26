
rule VirTool_Win32_Obfuscator_IN{
	meta:
		description = "VirTool:Win32/Obfuscator.IN,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 34 08 8b 34 b3 2b 74 82 10 33 34 82 56 8d 34 08 8b 7d fc 8d 3c b7 5e 89 37 8b 74 82 20 01 34 82 8b 74 82 30 01 74 82 10 40 83 f8 04 72 d1 83 c1 04 3b 4d 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule VirTool_Win32_Obfuscator_AON{
	meta:
		description = "VirTool:Win32/Obfuscator.AON,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 c7 00 6a 30 66 c7 40 02 5e 64 66 c7 40 04 ad 8b 66 c7 40 06 40 10 66 c7 40 08 8b 70 66 c7 40 0a 3c 0f 66 c7 40 0c b7 48 66 c7 40 0e 38 8b 66 c7 40 10 7c 24 66 c7 40 12 04 89 66 c7 40 14 4f fc 66 c7 40 16 fc f3 66 c7 40 18 a4 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
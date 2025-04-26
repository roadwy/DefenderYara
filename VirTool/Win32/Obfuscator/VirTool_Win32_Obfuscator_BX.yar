
rule VirTool_Win32_Obfuscator_BX{
	meta:
		description = "VirTool:Win32/Obfuscator.BX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 c3 00 00 01 00 81 fb 00 00 00 80 75 05 bb 00 00 f0 bf e8 ?? ?? ?? ?? 83 f8 00 74 e3 66 81 3b 4d 5a 75 dc 8b 43 3c 03 c3 66 81 38 50 45 75 d0 f6 40 17 20 74 ca 8b 40 78 03 c3 8b 50 0c 03 d3 81 3a 4b 45 52 4e 75 b8 81 7a 04 45 4c 33 32 75 af } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
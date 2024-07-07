
rule VirTool_Win32_Obfuscator_BV{
	meta:
		description = "VirTool:Win32/Obfuscator.BV,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 66 8b 02 3d 4d 5a 00 00 74 90 01 01 33 c0 e9 90 01 02 00 00 8b 8d 90 01 02 ff ff 8b 55 90 01 01 03 51 3c 89 95 90 01 02 ff ff 8b 85 90 01 02 ff ff 81 38 50 45 00 00 74 90 01 01 33 c0 e9 90 01 02 00 00 6a 40 68 00 10 00 00 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
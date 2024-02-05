
rule VirTool_Win32_Obfuscator_YA{
	meta:
		description = "VirTool:Win32/Obfuscator.YA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 3d dc 70 40 00 81 f7 90 01 04 89 3d dc 70 40 00 31 0a 8b 1d 2b 70 40 00 81 cb 90 01 04 89 1d 2b 70 40 00 29 0a 81 2a 90 01 04 f7 12 81 02 90 01 04 81 32 90 01 04 8b 35 14 72 40 00 31 d6 89 35 14 72 40 00 f7 12 c1 0a 90 01 01 8b 3d 59 72 40 00 31 cf 89 3d 59 72 40 00 83 c2 04 48 0f 85 99 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
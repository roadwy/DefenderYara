
rule VirTool_Win32_Obfuscator_AIU{
	meta:
		description = "VirTool:Win32/Obfuscator.AIU,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe7 03 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 48 8b 54 24 4c 8a 54 24 13 2c 07 02 c2 83 44 24 40 01 88 44 24 13 8a 44 24 27 0f b6 c0 99 83 d1 00 3b ca 0f 82 90 01 01 ff ff ff 0f 87 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_1 = {c7 45 f4 65 54 00 00 c7 45 f8 7a 0c 00 00 c7 45 fc df 34 00 00 8b 45 fc 8b 75 f8 69 c0 bf 09 00 00 33 d2 f7 f6 8b 55 f4 8b 75 08 } //00 00 
	condition:
		any of ($a_*)
 
}
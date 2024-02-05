
rule VirTool_Win32_CryptInject_YA_MTB{
	meta:
		description = "VirTool:Win32/CryptInject.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 00 8b 4d f4 8a 04 08 88 45 f0 8b 45 08 8b 00 8b 4d f4 8a 44 01 01 88 45 f3 8b 45 08 8b 00 8b 4d f4 8a 44 01 02 88 45 f1 8b 45 08 8b 00 8b 4d f4 8a 44 01 03 88 45 f2 0f b6 45 f0 0f b6 4d f2 c1 e1 02 81 e1 c0 00 00 00 0b c1 88 45 f0 0f b6 45 f3 0f b6 4d f2 c1 e1 04 81 e1 c0 00 00 00 0b c1 88 45 f3 0f b6 45 f1 0f b6 4d f2 c1 e1 06 81 e1 c0 00 00 00 0b c1 88 45 f1 8b 45 f8 03 45 fc 8a 4d f0 88 08 8b 45 fc 40 89 45 fc 8b 45 f8 03 45 fc 8a 4d f3 88 08 8b 45 fc 40 89 45 fc 8b 45 f8 03 45 fc 8a 4d f1 88 08 8b 45 fc 40 89 45 fc e9 31 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
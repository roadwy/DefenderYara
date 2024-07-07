
rule VirTool_Win32_CeeInject_GJ{
	meta:
		description = "VirTool:Win32/CeeInject.GJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 09 8b 45 fc 83 c0 01 89 45 fc 81 7d fc 00 01 00 00 0f 8d 90 04 01 03 a0 2d f0 00 00 00 e9 90 04 01 03 a0 2d f0 00 00 00 e9 90 04 01 03 a0 2d f0 00 00 00 90 02 ff 8b 4d fc 8b 55 fc 89 94 8d f8 fb ff ff e9 90 01 02 ff ff c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 81 7d fc 00 01 00 00 0f 8d 90 01 02 00 00 e9 90 04 01 03 a0 2d f0 00 00 00 e9 90 04 01 03 a0 2d f0 00 00 00 90 00 } //1
		$a_03_1 = {6a 0b 8d 8d 4c ff ff ff 51 e8 90 01 02 ff ff 83 c4 10 e9 90 04 01 03 a0 2d f0 00 00 00 e9 90 04 01 03 a0 2d f0 00 00 00 90 00 } //1
		$a_03_2 = {41 0f b6 8c 0d f8 fe ff ff 89 8d f4 fe ff ff eb 90 04 01 03 08 2d 14 eb 90 04 01 03 06 2d 12 90 02 14 8b 95 e8 fe ff ff 03 95 ec fe ff ff 0f be 02 33 85 f4 fe ff ff 8b 8d e8 fe ff ff 03 8d ec fe ff ff 88 01 eb 90 04 01 03 08 2d 14 eb 90 04 01 03 06 2d 12 90 02 14 e9 90 01 02 ff ff 8b 85 e8 fe ff ff eb 90 04 01 03 08 2d 14 eb 90 04 01 03 06 2d 12 90 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=2
 
}
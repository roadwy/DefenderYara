
rule Trojan_Win32_Emotet_ibt{
	meta:
		description = "Trojan:Win32/Emotet!ibt,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 45 f0 83 c0 01 89 45 f0 81 7d f0 a5 02 00 00 7d 0f 8b 4d f0 8a 55 f0 88 94 0d 38 fd ff ff eb df c7 45 f0 00 00 00 00 eb 09 8b 45 f0 83 c0 01 89 45 f0 81 7d f0 a5 02 00 00 7d 63 8b 4d f0 0f b6 94 0d 38 fd ff ff 89 55 fc 8b 85 34 fd ff ff 03 45 fc 8b 4d 10 03 4d e8 0f be 11 03 c2 25 ff 00 00 00 89 85 34 fd ff ff } //01 00 
		$a_03_1 = {6a 00 6a 00 ff 15 90 01 04 8b 55 08 03 55 f0 0f b6 02 8b 4d fc 03 4d ec 0f b6 d1 0f b6 8c 15 38 fd ff ff 33 c1 8b 55 08 03 55 f0 88 02 e9 ce fe ff ff 8b 4d e4 33 cd e8 b2 1e 03 00 8b e5 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
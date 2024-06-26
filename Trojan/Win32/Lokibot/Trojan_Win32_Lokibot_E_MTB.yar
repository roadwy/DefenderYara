
rule Trojan_Win32_Lokibot_E_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0b 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 55 08 03 55 f8 b0 90 01 01 e8 90 01 02 ff ff ff 45 f8 81 7d f8 90 01 04 75 e7 ff 65 08 90 00 } //01 00 
		$a_02_1 = {8b 06 03 c3 73 05 e8 90 01 04 50 68 90 01 04 ff 15 90 01 03 00 ff 06 81 3e 90 01 02 00 00 75 df 90 00 } //01 00 
		$a_02_2 = {8b 4d 08 03 4d fc b2 90 01 01 8b 45 fc e8 90 01 02 ff ff ff 45 fc 81 7d fc 90 01 04 75 e4 ff 65 08 90 00 } //01 00 
		$a_02_3 = {ff 45 f8 81 7d f8 90 0a 1f 00 b1 90 01 01 8b 55 f8 8b 45 08 e8 90 01 04 ff 45 f8 81 7d f8 90 01 02 00 00 75 e7 ff 65 08 90 00 } //01 00 
		$a_00_4 = {55 8b ec 83 c4 f8 89 55 f8 88 45 ff 8b 45 f8 8a 55 ff 30 10 59 59 5d c3 } //01 00 
		$a_00_5 = {55 8b ec ff 75 0c 90 8a 45 08 5a 30 02 90 90 5d c2 08 00 } //01 00 
		$a_00_6 = {55 8b ec 83 c4 f0 89 4d f4 88 55 fb 89 45 fc 8b 45 f4 89 45 fc 8a 45 fb 88 45 f3 8b 45 fc 8a 00 88 45 f2 8a 45 f2 32 45 f3 8b 55 fc 88 02 8b e5 5d c3 } //01 00 
		$a_00_7 = {55 8b ec 83 c4 f0 88 4d f7 89 55 f8 89 45 fc 8b 45 fc 03 45 f8 89 45 f0 8b 45 f0 8a 00 88 45 f6 8a 45 f6 32 45 f7 8b 55 f0 88 02 8b e5 5d c3 } //01 00 
		$a_00_8 = {55 8b ec 83 c4 ec 88 4d f7 89 55 f8 89 45 fc 8b 45 fc 03 45 f8 89 45 f0 8b 45 f0 8a 00 88 45 f6 8b 45 f0 89 45 ec 8a 45 f6 30 45 f7 8b 45 ec 8a 55 f7 88 10 8b e5 5d c3 } //01 00 
		$a_02_9 = {64 ff 30 64 89 20 83 2d 90 01 03 00 01 0f 83 90 01 02 00 00 90 02 4f 68 90 01 03 00 64 ff 30 64 89 20 90 00 } //01 00 
		$a_02_10 = {64 ff 30 64 89 20 ff 05 90 01 03 00 33 c0 5a 59 59 64 89 10 68 90 01 03 00 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Lokibot_RI_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f6 85 d2 75 90 02 1f 8b c3 03 c1 90 02 1f 80 30 9d 90 02 1f 41 81 f9 0f 08 01 00 75 90 00 } //0a 00 
		$a_03_1 = {33 d2 f7 f3 85 d2 75 90 02 1f 8b c6 03 c1 90 02 1f b2 90 02 1f 30 10 90 02 1f 41 81 f9 90 01 04 75 90 00 } //0a 00 
		$a_03_2 = {33 d2 f7 f3 85 d2 75 90 02 1f 8b 90 01 01 03 d1 90 02 1f b0 90 02 1f 30 02 90 02 1f 41 81 f9 0d 24 01 00 75 90 00 } //05 00 
		$a_01_3 = {90 90 90 90 90 8a 84 85 e4 fb ff ff 32 45 eb 8b 55 ec 88 02 90 90 46 ff 4d e4 0f 85 } //05 00 
		$a_03_4 = {25 ff 00 00 00 89 84 bd 90 01 04 90 90 8b c6 90 0a 3f 00 8b f8 90 90 90 02 05 8a 84 9d 90 1b 00 90 02 05 8b 94 bd 90 1b 00 89 94 9d 90 1b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Lokibot_H_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 90 02 1f 6a 40 68 00 30 00 00 68 90 01 04 6a 00 e8 90 01 03 ff 90 00 } //05 00 
		$a_02_1 = {8a 04 02 88 45 eb 90 02 9f 8a 55 eb 33 c2 90 02 20 8b 55 f0 88 02 90 02 20 ff 45 f4 ff 4d e0 0f 85 90 01 02 ff ff 90 00 } //05 00 
		$a_02_2 = {8a 04 02 88 45 f7 90 02 9f 8a 55 f7 33 c2 90 02 20 8b 55 e4 88 02 90 02 20 ff 45 f0 ff 4d e0 0f 85 90 01 02 ff ff 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 e0 } //1d 04 
	condition:
		any of ($a_*)
 
}
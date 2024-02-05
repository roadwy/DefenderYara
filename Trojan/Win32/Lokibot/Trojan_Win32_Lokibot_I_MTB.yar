
rule Trojan_Win32_Lokibot_I_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 68 90 01 04 6a 00 e8 90 01 03 ff 90 00 } //05 00 
		$a_02_1 = {8b 45 f8 03 45 f0 89 45 ec 90 02 7f 25 ff 00 00 00 89 84 bd 90 01 02 ff ff 90 02 2f 8a 02 88 45 e7 90 02 4f 8a 84 85 90 01 02 ff ff 32 45 e7 8b 4d ec 88 01 90 02 4f ff 45 f0 42 ff 4d e0 0f 85 90 01 01 ff ff ff 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 08 } //22 04 
	condition:
		any of ($a_*)
 
}
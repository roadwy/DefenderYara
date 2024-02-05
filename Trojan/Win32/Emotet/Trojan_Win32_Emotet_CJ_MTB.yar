
rule Trojan_Win32_Emotet_CJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CJ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 f0 0f b6 02 8b 4d fc 03 4d ec 0f b6 d1 0f b6 8c 15 90 fc ff ff 33 c1 8b 55 08 03 55 f0 88 02 e9 } //01 00 
		$a_01_1 = {89 45 fc 8b 4d f8 03 4d fc 81 e1 ff 00 00 00 89 4d f8 8b 55 f8 0f b6 84 15 90 fc ff ff 89 45 ec 8b 4d f4 8a 55 ec 88 94 0d 90 fc ff ff 8b 45 f8 8a 4d fc 88 8c 05 90 fc ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
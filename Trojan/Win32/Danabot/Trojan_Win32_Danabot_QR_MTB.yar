
rule Trojan_Win32_Danabot_QR_MTB{
	meta:
		description = "Trojan:Win32/Danabot.QR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 e0 8b 45 f4 31 45 ec 8b 45 f4 31 45 e8 8b 45 f4 31 45 e4 8b 45 f4 31 45 e0 8b 45 e4 f7 6d ec f7 6d e8 03 45 f8 33 45 e0 89 45 f8 ff 45 f0 ff 4d d4 0f } //00 00 
	condition:
		any of ($a_*)
 
}
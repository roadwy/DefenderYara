
rule Trojan_Win32_Qakbot_BX_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 5d d8 03 5d b4 2b d8 6a 00 e8 90 02 04 03 d8 8b 45 ec 31 18 6a 00 e8 90 02 04 8b d8 8b 45 e8 83 c0 04 03 d8 6a 00 e8 90 02 04 2b d8 6a 00 e8 90 02 04 03 d8 6a 00 e8 90 02 04 2b d8 89 5d e8 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
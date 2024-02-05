
rule Trojan_Win32_Qakbot_BU_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 8b 55 ec 01 02 6a 00 e8 90 02 04 8b 55 d8 03 55 e4 03 55 e8 2b d0 8b 45 ec 31 10 83 45 e8 04 e8 90 02 04 bb 04 00 00 00 2b d8 e8 90 02 04 03 d8 01 5d ec 8b 45 e8 3b 45 e0 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
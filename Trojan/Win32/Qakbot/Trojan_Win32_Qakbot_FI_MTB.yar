
rule Trojan_Win32_Qakbot_FI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 18 6a 00 e8 90 01 04 8b 5d c4 03 5d a4 2b d8 6a 00 e8 90 01 04 03 d8 89 5d a0 6a 00 e8 90 01 04 8b 5d a0 2b d8 6a 00 e8 90 01 04 03 d8 8b 45 d8 33 18 89 5d a0 6a 00 e8 90 01 04 8b 5d a0 2b d8 6a 00 e8 90 01 04 03 d8 8b 45 d8 89 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
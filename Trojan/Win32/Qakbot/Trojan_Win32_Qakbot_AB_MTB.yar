
rule Trojan_Win32_Qakbot_AB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b d1 89 55 90 01 01 a1 90 01 04 03 45 90 01 01 8a 4d 90 01 01 88 08 e9 90 0a 30 00 89 45 90 01 01 0f b6 0d 90 01 04 8b 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b d0 4a a1 90 01 04 89 10 a1 90 01 04 03 05 90 01 04 a3 90 01 04 6a 00 e8 90 01 04 8b 1d 90 01 04 2b d8 4b 6a 00 e8 90 01 04 2b d8 4b 6a 00 e8 90 01 04 03 d8 a1 90 01 04 33 18 89 1d 90 01 04 6a 00 e8 90 01 04 03 05 90 01 04 8b 15 90 01 04 89 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
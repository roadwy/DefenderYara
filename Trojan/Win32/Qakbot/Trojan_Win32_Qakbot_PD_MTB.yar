
rule Trojan_Win32_Qakbot_PD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c8 89 4d 90 01 01 0f b6 15 90 01 04 8b 45 90 01 01 2b c2 89 45 90 01 01 0f b6 0d 90 01 04 8b 55 90 01 01 2b d1 89 55 90 01 01 0f b6 05 90 01 04 33 45 90 01 01 89 45 90 01 01 8b 0d 90 01 04 03 4d 90 01 01 8a 55 90 01 01 88 11 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
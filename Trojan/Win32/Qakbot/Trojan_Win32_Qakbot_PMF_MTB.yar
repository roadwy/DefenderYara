
rule Trojan_Win32_Qakbot_PMF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4b 2b d8 6a 00 e8 90 02 04 03 d8 8b 45 d8 33 18 89 5d a0 6a 00 e8 90 02 04 8b 5d a0 2b d8 6a 00 e8 90 02 04 03 d8 8b 45 d8 89 18 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 6a 00 e8 90 02 04 8b 5d d8 83 c3 04 03 5d a4 2b d8 6a 00 e8 90 02 04 03 d8 89 5d d8 8b 45 a8 3b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
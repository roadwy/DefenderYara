
rule Trojan_Win32_Qakbot_EE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 90 01 04 03 d8 a1 90 01 04 01 18 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 48 8b 15 90 01 04 33 02 a3 90 01 04 a1 90 01 04 8b 15 90 01 04 89 02 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
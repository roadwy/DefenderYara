
rule Trojan_Win32_Qakbot_SAT_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 10 a1 5c 90 01 03 03 05 90 01 04 a3 90 01 04 6a 90 01 01 e8 90 01 04 03 05 90 01 04 8b 15 90 01 04 33 02 a3 90 01 04 a1 90 01 04 8b 15 90 01 04 89 10 a1 90 01 04 83 c0 90 01 01 a3 90 01 04 33 c0 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
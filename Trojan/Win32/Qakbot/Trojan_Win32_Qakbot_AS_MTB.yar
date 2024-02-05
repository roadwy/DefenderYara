
rule Trojan_Win32_Qakbot_AS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 } //02 00 
		$a_03_1 = {8b 55 a0 2b d0 4a 8b 45 d8 33 10 89 55 a0 6a 00 e8 90 02 04 8b d8 03 5d a0 6a 00 e8 90 02 04 03 d8 6a 00 e8 90 02 04 03 d8 6a 00 e8 90 02 04 03 d8 8b 45 d8 89 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
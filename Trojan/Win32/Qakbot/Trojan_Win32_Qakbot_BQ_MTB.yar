
rule Trojan_Win32_Qakbot_BQ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 2b d8 a1 90 02 04 33 18 89 1d 90 00 } //01 00 
		$a_03_1 = {8b 12 03 15 90 02 04 03 c2 8b 15 90 02 04 89 02 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Qakbot_EW_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 d8 8b 55 a8 01 10 8b 45 d8 8b 00 8b 55 c4 03 55 a8 03 55 ac 4a 33 c2 89 45 a0 6a 00 e8 90 01 04 8b 5d a0 2b d8 6a 00 e8 90 01 04 03 d8 8b 45 d8 89 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
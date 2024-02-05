
rule Trojan_Win32_Qakbot_PN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 bb 04 00 00 00 eb 2c 03 c1 89 45 f0 eb 37 03 41 18 89 45 f4 eb e7 } //00 00 
	condition:
		any of ($a_*)
 
}
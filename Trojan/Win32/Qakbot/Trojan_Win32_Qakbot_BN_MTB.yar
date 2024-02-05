
rule Trojan_Win32_Qakbot_BN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 1c 28 83 c5 04 0f af 5e 70 8b 86 90 01 04 8b d3 c1 ea 08 88 14 01 8b 86 90 01 04 2b 86 90 01 04 ff 86 90 01 04 05 90 01 04 01 86 90 01 04 8b 86 90 01 04 8b 8e 90 01 04 83 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_BN_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 8b 55 ec 01 02 8b 45 b8 03 45 e8 89 45 b4 68 90 02 04 e8 90 02 04 8b d8 8b 45 d8 03 45 b4 03 d8 68 90 02 04 e8 90 02 04 03 d8 8b 45 ec 31 18 68 90 02 04 e8 90 02 04 8b d8 8b 45 e8 83 c0 04 03 d8 68 90 02 04 e8 90 02 04 2b d8 89 5d e8 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
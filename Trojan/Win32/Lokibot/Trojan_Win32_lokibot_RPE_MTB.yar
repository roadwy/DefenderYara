
rule Trojan_Win32_lokibot_RPE_MTB{
	meta:
		description = "Trojan:Win32/lokibot.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 28 03 c2 8a 0c 38 39 9c 24 c0 00 00 00 74 07 b8 d0 39 57 00 2b c2 42 88 08 3b d6 7c e0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_lokibot_RPE_MTB_2{
	meta:
		description = "Trojan:Win32/lokibot.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 16 00 00 06 0a 00 06 72 64 01 00 70 7d 0d 00 00 04 28 08 00 00 06 06 fe 06 17 00 00 06 73 19 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b 07 28 03 00 00 06 6f 1c 00 00 0a 0c 12 02 28 1d 00 00 0a 00 2a } //00 00 
	condition:
		any of ($a_*)
 
}
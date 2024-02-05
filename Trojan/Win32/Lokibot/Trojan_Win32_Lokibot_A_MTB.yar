
rule Trojan_Win32_Lokibot_A_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 45 f8 43 81 7d f8 90 0a 30 00 8a 03 34 90 01 01 88 07 90 05 10 01 90 8a 07 e8 90 01 04 90 05 10 01 90 83 06 01 73 90 01 01 e8 90 01 04 90 05 10 01 90 ff 45 f8 43 81 7d f8 90 01 04 75 90 01 01 90 05 10 01 90 8b 4d fc 90 05 10 01 90 81 c1 90 01 04 90 05 10 01 90 ff d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
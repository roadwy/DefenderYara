
rule Trojan_Win32_lokibot_RPD_MTB{
	meta:
		description = "Trojan:Win32/lokibot.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0e 80 79 0f 00 89 08 75 40 8b 51 08 80 7a 0f 00 75 1a 8b 0a 80 79 0f 00 75 0f eb 03 8d 49 00 8b d1 8b 0a 80 79 0f 00 74 f6 89 16 c3 } //01 00 
		$a_01_1 = {8b 49 04 80 79 0f 00 75 12 8b 16 3b 51 08 75 0b 89 0e 8b 49 04 80 79 0f 00 74 ee 89 0e c3 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Lokibot_AR_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {29 d2 03 11 bb 90 01 04 81 eb 90 01 04 81 c3 90 01 04 81 c3 90 01 04 4a 39 1a eb 90 00 } //01 00 
		$a_03_1 = {89 d3 8b 0f 31 f1 90 02 05 11 0c 18 90 00 } //01 00 
		$a_01_2 = {46 ff 37 59 31 f1 39 c1 75 } //01 00 
		$a_01_3 = {01 c2 8b 1a ff d3 } //00 00 
		$a_00_4 = {78 9d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Lokibot_AR_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 ff 30 64 89 20 33 c0 a3 90 01 03 00 90 05 10 01 90 b8 00 00 00 00 f7 f0 90 00 } //01 00 
		$a_03_1 = {ff 75 fc 5b 81 c3 90 01 02 00 00 53 c3 90 00 } //01 00 
		$a_03_2 = {8a 02 88 45 90 01 01 90 05 10 01 90 8b 84 9d 90 01 02 ff ff 03 84 bd 90 01 02 ff ff 90 05 10 01 90 25 ff 00 00 80 79 90 01 01 48 0d 00 ff ff ff 40 8a 84 85 90 01 02 ff ff 32 45 90 01 01 8b 4d 90 01 01 88 01 90 05 10 01 90 ff 45 90 01 01 42 ff 4d 90 01 01 0f 85 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
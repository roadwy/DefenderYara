
rule Trojan_Win32_Lokibot_SL_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {53 56 51 8b d8 8b f4 90 05 10 01 90 56 6a 40 52 53 e8 90 01 04 90 02 10 33 c0 89 06 90 05 10 01 90 8b 06 03 c3 73 05 e8 90 01 04 50 90 02 06 ff 15 90 01 04 90 05 10 01 90 ff 06 81 3e 90 01 04 75 90 00 } //01 00 
		$a_03_1 = {55 8b ec eb 90 01 01 90 05 10 01 90 8a 45 08 30 90 01 01 eb 90 01 01 90 05 10 01 90 8b 7d 0c 90 05 10 01 90 eb 90 00 } //00 00 
		$a_00_2 = {5d 04 00 } //00 56 
	condition:
		any of ($a_*)
 
}
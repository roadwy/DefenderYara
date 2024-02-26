
rule Trojan_Win32_Pikabot_CHY_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.CHY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 0c 02 83 c2 04 a1 90 01 04 8b 0d 90 01 04 83 c0 ee 8b 35 90 01 04 33 c8 a1 90 01 04 2b c1 89 0d 90 01 04 2d 98 fd 18 00 0f af 05 90 01 04 a3 90 01 04 a1 90 01 04 01 05 90 01 04 a1 90 01 04 8d 04 45 57 5e f9 ff 03 46 64 a3 90 01 04 81 fa 90 01 03 00 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
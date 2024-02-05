
rule Trojan_Win32_Zbot_GQQ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {89 7d fc 7d 0b 83 ce ff d3 ee 83 4d f8 ff eb 0d 83 c1 e0 83 c8 ff 33 f6 d3 e8 89 45 f8 a1 a0 95 40 00 8b d8 89 75 f4 3b df eb 14 8b 4b 04 8b 3b 23 4d f8 23 fe 0b cf 75 0b 83 c3 14 3b 5d fc 89 5d 08 72 e7 } //01 00 
		$a_80_1 = {59 74 6f 7a 6d 75 71 64 61 } //Ytozmuqda  01 00 
		$a_80_2 = {48 61 77 75 71 79 69 71 6f } //Hawuqyiqo  00 00 
	condition:
		any of ($a_*)
 
}
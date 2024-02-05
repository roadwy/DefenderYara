
rule Trojan_Win32_Zbot_RPX_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 8b 0d 30 00 00 00 f8 81 e8 00 00 00 00 f8 f5 8d 00 3c 8f c0 c8 28 60 60 60 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c6 33 d2 b9 b0 03 00 00 f7 f1 8a 55 ff 8b c8 8a 45 fe 80 c1 02 d2 ea 8d 8e d2 fd ff ff d2 e0 8b 4d f4 0a d0 8b c7 69 c0 8f 00 00 00 23 c6 25 bb 01 00 00 88 54 08 df } //00 00 
	condition:
		any of ($a_*)
 
}
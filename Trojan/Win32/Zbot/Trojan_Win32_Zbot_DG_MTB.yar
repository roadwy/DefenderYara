
rule Trojan_Win32_Zbot_DG_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DG!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 4d f4 83 c1 01 89 4d f4 8b 55 f4 3b 55 f8 7d 69 8b 45 10 3b 45 fc 7f 0b 8b 4d 10 03 4d fc 89 4d f0 eb 09 8b 55 10 2b 55 fc 89 55 f0 8b 45 08 03 45 f4 0f be 08 8b 75 fc 33 75 10 83 c6 58 8b 45 f0 99 f7 fe 33 ca 8b 55 08 03 55 f4 88 0a 83 7d fc 3a 7e 09 c7 45 fc 00 00 00 00 eb 1a 83 7d 10 5a 7e 0b 8b 45 fc 83 c0 02 89 45 fc eb 09 8b 4d fc 83 c1 03 89 4d fc eb 86 } //00 00 
	condition:
		any of ($a_*)
 
}
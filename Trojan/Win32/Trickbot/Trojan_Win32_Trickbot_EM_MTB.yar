
rule Trojan_Win32_Trickbot_EM_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be c8 81 e1 90 01 04 8b c1 c1 e8 03 83 e1 07 8d 14 30 b0 01 d2 e0 8d 7f 01 08 02 8a 07 84 c0 75 dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.EM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 08 00 00 00 6b c2 00 8b 4d fc 8b 55 f4 8b 49 24 2b 0c 02 03 4d fc 89 4d d8 ba 08 00 00 00 6b c2 00 8b 4d fc 8b 55 f4 8b 49 1c 2b 0c 02 03 4d fc 89 4d d4 ba 08 00 00 00 6b c2 00 8b 4d fc 8b 55 f4 8b 49 20 2b 0c 02 03 4d fc 89 4d e0 c7 45 ec 00 00 00 00 8b 55 fc 8b 42 18 89 45 f0 8b 4d f0 d1 e9 89 4d f8 8b 55 f0 83 c2 01 89 55 e8 } //00 00 
	condition:
		any of ($a_*)
 
}
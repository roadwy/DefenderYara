
rule Trojan_Win32_Trickbot_EG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {99 f7 fd 89 d1 8b 7c 94 90 01 01 8d 04 1f 99 f7 fd 89 d3 8b 44 90 01 02 89 44 90 01 02 89 fa 0f b6 c2 89 44 90 01 02 03 44 90 01 02 99 f7 fd 8b 44 90 01 02 8b 54 90 01 02 30 04 32 46 81 fe 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_EG_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6b c0 25 83 c0 56 99 6a 7f 59 f7 f9 88 55 90 01 01 33 c0 40 d1 e0 0f b6 80 90 01 04 6b c0 25 83 c0 56 99 6a 7f 59 f7 f9 88 55 90 01 01 33 c0 40 6b c0 03 0f b6 80 90 01 04 6b c0 25 83 c0 56 99 6a 7f 59 f7 f9 88 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_EG_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 55 e8 0f b6 02 0f b6 4d e7 33 c1 8b 55 e8 2b 55 08 0f b6 ca 81 e1 e0 00 00 00 33 c1 8b 55 e8 88 02 } //01 00 
		$a_03_1 = {8b 55 ec 83 c2 01 89 55 ec 8b 45 ec 3b 45 fc 0f 8d 90 01 04 8b 4d f0 03 4d ec 0f be 11 81 f2 e0 00 00 00 88 55 e7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_EG_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2b c1 83 c4 48 8b d0 c1 e2 05 2b d0 03 d6 ff } //01 00 
		$a_02_1 = {57 0f af 35 90 01 04 8b f9 8b c1 c1 e7 05 2b f9 2b c6 c1 e7 03 8b d0 8b df 8b 7c 90 01 02 c1 e2 06 8b 54 90 01 02 2b d3 8d 1c 90 01 01 8d 2c 90 01 01 8b 5c 3a 90 01 01 03 dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
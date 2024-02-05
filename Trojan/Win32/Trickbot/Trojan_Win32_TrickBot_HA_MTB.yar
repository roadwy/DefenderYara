
rule Trojan_Win32_TrickBot_HA_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 33 d2 f7 f3 41 8a 44 55 00 30 44 31 ff 3b cf 75 } //01 00 
		$a_01_1 = {0f b6 11 c1 c8 0d 41 03 c2 80 79 ff 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBot_HA_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 12 33 db 43 2b df 0f af d8 8b 45 0c 89 4d f8 8b 0d 90 01 04 2b d9 6b c9 05 03 1d 90 01 04 03 5d fc 03 d8 8b 45 f4 0f b6 04 30 03 c2 33 d2 f7 35 90 01 04 2b d1 03 d7 03 15 90 01 04 8a 04 32 30 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
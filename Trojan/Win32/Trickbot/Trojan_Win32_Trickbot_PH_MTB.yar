
rule Trojan_Win32_Trickbot_PH_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 0c 16 8b 54 24 90 01 01 8b 34 24 8a 2c 32 30 e9 8b 54 24 90 01 01 88 0c 32 46 66 8b 7c 24 90 01 01 66 81 c7 90 01 02 66 89 7c 24 90 01 01 89 5c 24 90 01 01 89 74 24 90 01 01 8b 5c 24 90 01 01 8b 54 24 90 01 01 01 db 11 d2 89 5c 24 90 01 01 89 54 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 54 24 90 01 01 39 d6 0f 84 90 00 } //01 00 
		$a_02_1 = {8b 74 24 10 8a 2c 16 88 2c 1e 88 0c 16 c7 44 24 50 90 01 04 0f b6 14 1e 8b 7c 24 04 01 fa 88 d1 0f b6 d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
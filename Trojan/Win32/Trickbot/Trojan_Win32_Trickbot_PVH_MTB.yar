
rule Trojan_Win32_Trickbot_PVH_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 30 84 0d 90 01 01 d1 ff ff 50 53 90 09 08 00 0f b6 84 90 01 02 fe ff ff 90 00 } //01 00 
		$a_00_1 = {36 50 4f 58 4b 45 45 56 51 33 38 53 44 4a 34 56 59 34 35 } //01 00 
		$a_00_2 = {42 42 57 59 4e 52 43 47 31 43 33 35 50 4c 52 58 32 57 36 } //01 00 
		$a_00_3 = {35 50 31 44 48 43 32 51 34 41 58 43 4b 31 57 47 50 4d 5a } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Trickbot_FA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 41 01 b9 4b 40 00 00 f7 f1 bb 4b 40 00 00 8b ca 0f b6 04 31 33 d2 03 c7 bf 4b 40 00 00 f7 f7 8b fa 8b 55 f8 8a 14 0a 8a 04 37 88 04 31 88 14 37 0f b6 04 31 0f b6 d2 03 c2 33 d2 f7 f3 8b 45 fc 40 89 45 fc 2b 15 90 01 04 2b 15 90 01 04 2b 15 90 01 04 03 55 f4 8a 1c 32 8b 55 f0 30 5c 02 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_Win32_Trickbot_PF_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 51 0c 8b 59 14 8b 4d 90 01 01 2b d3 83 c1 05 66 0f b6 04 10 66 99 66 f7 f9 66 8b da 8d 55 90 01 01 52 ff d6 8a 04 38 8d 4d 90 01 01 51 32 d8 ff d6 8b 4d 90 01 01 88 1c 38 8b 7d 0c b8 01 00 00 00 03 c8 33 db 89 4d 90 01 01 eb 90 00 } //01 00 
		$a_02_1 = {8b 45 d4 8b 95 90 01 04 8b 5d 90 01 01 8b 48 0c 66 0f b6 04 11 66 8b cb 66 83 c1 05 66 99 0f 80 90 01 04 66 f7 f9 66 8b ca 8b 16 8b 42 0c 8b 95 90 01 04 66 0f b6 04 10 33 c8 ff 15 90 01 04 8b 0e 8b 51 0c 88 04 3a b8 01 00 00 00 66 03 c3 bf 02 00 00 00 0f 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_TelegramRat_AET_MTB{
	meta:
		description = "Trojan:BAT/TelegramRat.AET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {13 1e 16 13 1f 2b 75 00 7e 25 00 00 04 11 1f 73 a7 00 00 0a 12 11 fe 15 10 00 00 1b 11 11 12 11 fe 15 10 00 00 1b 11 11 14 12 12 fe 15 3d 00 00 01 11 12 } //01 00 
		$a_01_1 = {47 00 65 00 74 00 20 00 61 00 6c 00 6c 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 73 00 20 00 6c 00 69 00 73 00 74 00 20 00 73 00 6f 00 72 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 61 00 6c 00 70 00 68 00 61 00 62 00 65 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}
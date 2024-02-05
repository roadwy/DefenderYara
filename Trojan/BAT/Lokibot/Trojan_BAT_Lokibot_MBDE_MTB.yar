
rule Trojan_BAT_Lokibot_MBDE_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.MBDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {38 d5 01 00 00 06 07 02 7b 90 01 01 00 00 04 08 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 06 28 90 01 01 00 00 06 5a 02 7b 90 01 01 00 00 04 08 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 06 90 00 } //01 00 
		$a_01_1 = {62 34 62 38 32 61 32 66 2d 64 63 33 34 2d 34 61 61 39 2d 62 32 33 37 2d 64 33 30 31 37 65 63 38 62 65 65 65 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_Darkcomet_AKH_MTB{
	meta:
		description = "Trojan:BAT/Darkcomet.AKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 1a 5a 0a 06 8d 90 01 03 01 0c 02 25 13 07 2c 06 11 07 8e 69 2d 05 16 e0 0d 2b 09 11 07 16 8f 90 01 03 01 0d 08 25 13 07 2c 06 11 07 8e 69 2d 06 16 e0 13 04 2b 0a 11 07 16 8f 90 01 03 01 13 04 09 d3 11 04 d3 02 8e 69 08 8e 69 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
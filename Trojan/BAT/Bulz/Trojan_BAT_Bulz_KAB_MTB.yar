
rule Trojan_BAT_Bulz_KAB_MTB{
	meta:
		description = "Trojan:BAT/Bulz.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 9a 0b 07 17 8d 90 01 01 00 00 01 13 06 11 06 16 20 90 01 02 00 00 9d 11 06 6f 90 01 01 00 00 0a 16 9a 0c 07 17 8d 90 01 01 00 00 01 13 07 11 07 16 20 90 01 02 00 00 9d 11 07 6f 90 01 01 00 00 0a 17 9a 0d 08 09 28 90 01 01 00 00 06 11 05 17 58 13 05 11 05 11 04 8e 69 32 ad 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
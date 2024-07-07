
rule Trojan_BAT_Noon_KAD_MTB{
	meta:
		description = "Trojan:BAT/Noon.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 09 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0a 91 13 0c 08 11 0b 6f 90 01 01 00 00 0a 13 0d 02 07 11 09 28 90 01 01 00 00 06 13 0e 02 11 0c 11 0d 11 0e 28 90 01 01 00 00 06 13 0f 07 11 0a 11 0f 20 90 01 02 00 00 5d d2 9c 11 09 17 59 13 09 11 09 16 2f b2 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
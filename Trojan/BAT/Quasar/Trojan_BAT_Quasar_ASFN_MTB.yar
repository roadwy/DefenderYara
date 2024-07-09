
rule Trojan_BAT_Quasar_ASFN_MTB{
	meta:
		description = "Trojan:BAT/Quasar.ASFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 09 06 8e 69 5d 7e ?? 00 00 04 06 09 06 8e 69 5d 91 08 09 08 8e 69 5d 91 61 28 ?? ?? ?? 06 06 09 17 58 06 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 09 17 58 1e 2d 50 26 09 6a 06 8e 69 17 59 6a 07 17 58 6e 5a 31 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}

rule Trojan_BAT_RiseProStealer_AAXJ_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.AAXJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 5d 18 58 1b 58 1d 59 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1b 58 1d 59 91 61 28 90 01 01 00 00 0a 02 08 20 89 10 00 00 58 20 88 10 00 00 59 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 1b 2c 89 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 98 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
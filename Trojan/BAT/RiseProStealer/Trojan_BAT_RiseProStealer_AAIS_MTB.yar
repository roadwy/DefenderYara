
rule Trojan_BAT_RiseProStealer_AAIS_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.AAIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 8e 69 5d 7e 90 01 01 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 01 00 00 06 03 08 1b 58 1b 59 17 58 03 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 1e 2c ad 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
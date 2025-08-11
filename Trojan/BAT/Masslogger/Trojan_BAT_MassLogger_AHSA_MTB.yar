
rule Trojan_BAT_MassLogger_AHSA_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.AHSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 02 07 6f ?? 00 00 0a 1f 20 5d 1f 09 58 1f 19 5d 1f 10 5a 02 07 17 58 6f ?? 00 00 0a 1f 20 5d 1f 09 58 1f 19 5d 58 d2 9c 07 18 58 0b 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d c4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
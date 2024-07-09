
rule Trojan_BAT_Rhadamanthus_ABQD_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthus.ABQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 0b 07 6f ?? ?? ?? 0a 17 58 19 5b 0c 08 8d ?? ?? ?? 01 0d 16 13 05 2b 71 00 07 19 11 05 5a 6f ?? ?? ?? 0a 13 06 11 06 1f 39 fe 02 13 08 11 08 2c 0d 11 06 1f 41 59 1f 0a 58 d1 13 06 2b 08 11 06 1f 30 59 d1 13 06 07 19 11 05 5a 17 58 6f ?? ?? ?? 0a 13 07 11 07 1f 39 fe 02 13 09 11 09 2c 0d 11 07 1f 41 59 1f 0a 58 d1 13 07 2b 08 11 07 1f 30 59 d1 13 07 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
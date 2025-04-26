
rule Trojan_BAT_Remcos_FAH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 0a 03 08 1f 09 58 1e 59 03 8e 69 5d 91 59 20 ?? 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 16 2d 02 17 58 0c 08 6a 03 8e 1b 2c 01 69 17 59 6a 06 17 58 6e 5a 31 a8 0f 01 03 8e 69 17 59 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
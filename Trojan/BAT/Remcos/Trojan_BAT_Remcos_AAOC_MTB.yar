
rule Trojan_BAT_Remcos_AAOC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AAOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 15 09 5d 13 16 11 15 11 04 5d 13 17 07 11 16 91 13 18 08 11 17 6f ?? 00 00 0a 13 19 07 11 15 17 58 09 5d 91 13 1a 11 18 11 19 61 11 1a 59 20 00 01 00 00 58 13 1b 07 11 16 11 1b 20 00 01 00 00 5d d2 9c 00 11 15 17 59 13 15 11 15 16 fe 04 16 fe 01 13 1c 11 1c 2d a6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
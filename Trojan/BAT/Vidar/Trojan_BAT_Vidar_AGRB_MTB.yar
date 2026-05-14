
rule Trojan_BAT_Vidar_AGRB_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AGRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 07 6f ?? 00 00 0a 06 11 05 06 8e 69 5d 91 61 d2 9c 11 05 17 58 13 05 00 11 0a 17 58 13 0a 11 0a 08 19 5a fe 04 13 0b 11 0b 2d d0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
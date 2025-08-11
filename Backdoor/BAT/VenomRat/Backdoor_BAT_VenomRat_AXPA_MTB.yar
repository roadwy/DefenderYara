
rule Backdoor_BAT_VenomRat_AXPA_MTB{
	meta:
		description = "Backdoor:BAT/VenomRat.AXPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 1b 2b 1c 2b 21 73 ?? ?? 00 0a 25 72 ?? ?? 00 70 2b 17 2b 1c 2b 1d 2b 22 2b 27 de 2d 02 2b e2 28 ?? ?? 00 06 2b dd 0a 2b dc 28 ?? ?? 00 0a 2b e2 06 2b e1 28 ?? ?? 00 06 2b dc 6f ?? ?? 00 0a 2b d7 0b 2b d6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
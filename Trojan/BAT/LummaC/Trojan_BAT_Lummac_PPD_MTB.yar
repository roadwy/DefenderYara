
rule Trojan_BAT_Lummac_PPD_MTB{
	meta:
		description = "Trojan:BAT/Lummac.PPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 69 13 18 11 19 6e 11 1a 6a 61 69 13 1a 08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 1b 06 08 06 09 91 9c 06 09 11 1b 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 1c 02 11 13 8f 14 00 00 01 25 71 14 00 00 01 06 11 1c 91 61 d2 81 14 00 00 01 11 13 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
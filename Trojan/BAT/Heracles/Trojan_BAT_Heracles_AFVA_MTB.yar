
rule Trojan_BAT_Heracles_AFVA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AFVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 08 03 8e 69 5d 03 08 03 8e 69 5d 1b 58 1b 59 91 07 08 07 8e 69 5d 1c 58 1b 59 17 59 91 61 03 08 1c 58 1b 59 03 8e 69 5d 1c 58 1b 59 17 59 91 59 20 fc 00 00 00 58 1a 58 20 00 01 00 00 5d d2 9c 08 17 58 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
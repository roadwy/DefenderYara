
rule Trojan_BAT_AveMaria_AAYJ_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.AAYJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 8e 69 5d 7e ?? 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? 00 06 03 08 1c 58 1b 59 03 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 08 17 58 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
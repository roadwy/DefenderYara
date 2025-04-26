
rule Trojan_BAT_Heracles_EAFL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EAFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 08 91 66 d2 0d 07 08 09 19 63 09 1b 62 60 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 13 05 11 05 2d dd } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
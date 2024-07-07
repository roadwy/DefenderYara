
rule Trojan_BAT_DarkComet_ACU_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ACU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 17 da 02 03 07 91 03 07 17 da 91 65 b5 6f 90 01 03 06 9c 07 15 d6 0b 07 17 2f e3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
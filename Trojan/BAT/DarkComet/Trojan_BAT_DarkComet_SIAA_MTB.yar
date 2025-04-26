
rule Trojan_BAT_DarkComet_SIAA_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.SIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {15 59 91 61 ?? 08 20 0d 02 00 00 58 20 0c 02 00 00 59 1d 59 1d 58 ?? 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
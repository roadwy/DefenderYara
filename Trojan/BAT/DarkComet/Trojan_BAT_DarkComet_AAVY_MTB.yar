
rule Trojan_BAT_DarkComet_AAVY_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AAVY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 50 06 02 50 06 91 7e 03 00 00 04 06 7e 03 00 00 04 8e 69 5d 91 61 d2 9c 06 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
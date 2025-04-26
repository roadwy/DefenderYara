
rule Trojan_BAT_DarkComet_AGDJ_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AGDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 04 91 08 58 d2 13 05 09 11 04 17 58 91 08 58 d2 13 06 09 11 04 11 06 9c 09 11 04 17 58 11 05 9c 11 04 18 58 13 04 11 04 11 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
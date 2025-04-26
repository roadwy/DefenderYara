
rule Trojan_BAT_DarkComet_SEV_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.SEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 17 00 00 01 0d 09 28 16 00 00 0a 28 17 00 00 0a 72 21 00 00 70 6f 18 00 00 0a 28 02 00 00 06 13 04 72 7b 00 00 70 28 19 00 00 0a 73 1a 00 00 0a 13 05 11 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
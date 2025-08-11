
rule Trojan_BAT_DarkComet_ACM_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 84 95 d7 6e 20 ff 00 00 00 6a 5f b8 13 04 11 05 07 84 95 0d 11 05 07 84 11 05 11 04 84 95 9e 11 05 11 04 84 09 9e 08 11 09 02 11 09 91 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
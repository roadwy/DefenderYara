
rule Trojan_BAT_DarkComet_AKM_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 02 06 17 9a 28 ?? 00 00 0a 6f ?? 00 00 06 0b 02 06 19 9a 28 ?? 00 00 0a 6f ?? 00 00 06 0c 28 ?? 00 00 06 6f ?? 00 00 0a 09 72 ?? 00 00 70 06 18 9a 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
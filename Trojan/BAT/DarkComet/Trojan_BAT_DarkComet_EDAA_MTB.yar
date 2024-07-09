
rule Trojan_BAT_DarkComet_EDAA_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.EDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 12 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 28 ?? 00 00 0a 12 01 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 18 73 ?? 00 00 0a 0c 08 06 16 06 8e b7 6f ?? 00 00 0a 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}

rule Trojan_BAT_DarkComet_AOD_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AOD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 3b 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 03 06 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 06 04 58 03 6f ?? 00 00 0a 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 06 17 58 0a 06 02 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
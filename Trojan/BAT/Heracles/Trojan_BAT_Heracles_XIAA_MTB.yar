
rule Trojan_BAT_Heracles_XIAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.XIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 07 18 5a 6f ?? 00 00 0a 28 ?? 00 00 0a 1a 7e ?? 00 00 04 1f 34 7e ?? 00 00 04 1f 34 91 7e ?? 00 00 04 1f 11 91 61 20 f5 00 00 00 5f 9c 62 72 3d 04 00 70 03 07 18 5a 17 58 6f ?? 00 00 0a 28 ?? 00 00 0a 60 d2 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
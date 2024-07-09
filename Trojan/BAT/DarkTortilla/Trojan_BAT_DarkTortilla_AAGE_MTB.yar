
rule Trojan_BAT_DarkTortilla_AAGE_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 1f 1a 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 17 13 0a 38 ?? ff ff ff 00 07 11 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 17 13 0a 38 ?? ff ff ff 08 17 d6 0c 00 1d 13 0a 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
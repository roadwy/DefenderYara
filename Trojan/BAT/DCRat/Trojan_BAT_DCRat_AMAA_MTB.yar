
rule Trojan_BAT_DCRat_AMAA_MTB{
	meta:
		description = "Trojan:BAT/DCRat.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 0a 02 11 0a 91 03 11 0a 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20 ?? 00 00 00 38 ?? ?? ff ff 11 04 13 0c 38 ?? ?? ff ff 11 05 11 00 fe 04 13 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
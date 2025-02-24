
rule Trojan_BAT_DarkTortilla_AZHA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AZHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 02 11 05 91 20 f0 00 00 00 61 b4 9c 1f 09 13 09 2b 8a 11 05 17 d6 13 05 1c 13 09 38 ?? ff ff ff 11 05 11 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
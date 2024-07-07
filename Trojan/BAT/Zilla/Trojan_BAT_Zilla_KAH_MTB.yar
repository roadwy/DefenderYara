
rule Trojan_BAT_Zilla_KAH_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 15 11 04 11 15 91 20 90 01 01 00 00 00 61 d2 9c 11 15 17 58 13 15 11 15 11 04 8e 69 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
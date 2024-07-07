
rule Trojan_BAT_Heracle_KAH_MTB{
	meta:
		description = "Trojan:BAT/Heracle.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 08 11 05 91 07 11 04 93 28 90 01 01 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 05 17 58 13 05 11 05 08 8e 69 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
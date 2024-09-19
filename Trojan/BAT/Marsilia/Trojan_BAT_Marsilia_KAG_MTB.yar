
rule Trojan_BAT_Marsilia_KAG_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 11 04 06 11 04 91 18 59 20 ff 00 00 00 5f d2 9c 11 04 17 58 13 04 11 04 06 8e 69 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
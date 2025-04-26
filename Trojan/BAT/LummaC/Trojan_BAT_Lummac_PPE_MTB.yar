
rule Trojan_BAT_Lummac_PPE_MTB{
	meta:
		description = "Trojan:BAT/Lummac.PPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 35 12 1f 28 ?? 00 00 0a 12 35 28 ?? 00 00 0a 26 16 13 36 12 29 28 ?? 00 00 0a 28 ?? 00 00 0a 13 36 03 11 35 91 13 37 06 11 36 91 13 38 11 37 11 38 61 d2 13 37 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
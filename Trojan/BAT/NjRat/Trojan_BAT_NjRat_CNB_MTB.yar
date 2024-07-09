
rule Trojan_BAT_NjRat_CNB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.CNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 20 ?? ?? ?? ?? 13 10 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
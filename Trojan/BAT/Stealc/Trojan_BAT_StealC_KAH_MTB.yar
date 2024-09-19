
rule Trojan_BAT_StealC_KAH_MTB{
	meta:
		description = "Trojan:BAT/StealC.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 21 91 61 d2 81 ?? 00 00 01 11 07 17 58 13 07 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
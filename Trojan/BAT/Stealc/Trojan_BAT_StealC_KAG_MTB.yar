
rule Trojan_BAT_StealC_KAG_MTB{
	meta:
		description = "Trojan:BAT/StealC.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 22 91 61 d2 81 ?? 00 00 01 11 08 17 58 13 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
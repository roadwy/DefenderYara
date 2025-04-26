
rule Trojan_BAT_RisePro_KAB_MTB{
	meta:
		description = "Trojan:BAT/RisePro.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 30 61 d2 81 ?? 00 00 01 03 50 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}

rule Trojan_BAT_Ursu_KAA_MTB{
	meta:
		description = "Trojan:BAT/Ursu.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5f 69 95 61 d2 9c 11 ?? 17 58 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
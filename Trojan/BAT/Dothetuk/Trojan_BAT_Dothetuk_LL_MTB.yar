
rule Trojan_BAT_Dothetuk_LL_MTB{
	meta:
		description = "Trojan:BAT/Dothetuk.LL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 58 5e d2 61 d2 81 31 90 01 03 11 0c 11 07 5a 11 08 58 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
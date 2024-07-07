
rule Trojan_BAT_NjRAT_KAA_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 91 07 07 11 08 95 07 11 04 95 58 6e 20 90 01 01 00 00 00 6a 5f 69 95 61 d2 9c 11 07 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
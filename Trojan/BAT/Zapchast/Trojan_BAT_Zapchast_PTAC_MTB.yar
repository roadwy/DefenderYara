
rule Trojan_BAT_Zapchast_PTAC_MTB{
	meta:
		description = "Trojan:BAT/Zapchast.PTAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 6f 37 00 00 06 6f a1 00 00 0a a2 00 08 1a 72 d5 02 00 70 a2 00 08 28 ?? 00 00 0a 18 16 15 28 ?? 00 00 0a 26 00 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
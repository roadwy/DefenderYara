
rule Trojan_BAT_ZgRAT_J_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 70 20 00 01 00 00 14 14 14 6f 90 09 14 00 06 13 ?? 72 ?? 00 00 70 28 ?? 00 00 06 11 ?? 8e 69 26 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}

rule Trojan_BAT_DCRat_C_MTB{
	meta:
		description = "Trojan:BAT/DCRat.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 06 0b 07 28 04 00 00 0a 20 ?? 00 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 7d ?? 00 00 04 07 fe } //2
		$a_03_1 = {00 00 0a 20 00 00 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0a 06 28 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
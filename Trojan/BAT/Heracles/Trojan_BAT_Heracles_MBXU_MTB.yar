
rule Trojan_BAT_Heracles_MBXU_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 20 b3 15 00 00 28 ?? 00 00 0a 00 d0 ?? 00 00 01 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 06 72 01 00 00 70 6f ?? 00 00 0a 72 67 00 00 70 1f 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
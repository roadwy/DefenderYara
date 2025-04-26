
rule Trojan_BAT_Zapchast_PSZZ_MTB{
	meta:
		description = "Trojan:BAT/Zapchast.PSZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 37 00 00 0a 0a 03 02 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 06 02 07 6f 38 00 00 0a 00 00 de 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
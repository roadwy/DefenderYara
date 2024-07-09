
rule Trojan_BAT_Zapchast_PSZX_MTB{
	meta:
		description = "Trojan:BAT/Zapchast.PSZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 11 6f 1f 00 00 0a 13 12 11 0e 28 ?? 00 00 0a 13 13 00 20 00 04 00 00 8d 24 00 00 01 13 14 2b 0f 00 11 12 11 14 16 11 15 6f 21 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
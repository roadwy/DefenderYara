
rule Trojan_BAT_Formbook_AMAE_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 20 00 01 00 00 5e 13 [0-14] 17 13 [0-1e] 95 61 d2 9c 11 [0-14] 17 58 13 [0-0a] 07 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}

rule Trojan_BAT_Formbook_AMN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {95 58 20 ff 00 00 00 5f 13 [0-1e] 95 61 28 ?? 00 00 0a 9c 11 ?? 17 58 13 [0-0f] 6e 09 8e 69 6a fe } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
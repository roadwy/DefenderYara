
rule Trojan_BAT_Formbook_ZVI_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 16 fe 01 13 0c 11 0c 2c 35 00 02 08 09 6f ?? 00 00 0a 13 04 07 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 0e 04 2d 02 2b 0e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
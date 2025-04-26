
rule Trojan_BAT_Formbook_KAF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 18 d8 0a 06 1f ?? fe ?? 0d 09 2c ?? 1f ?? 0a 00 06 1f ?? 5d 16 fe } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
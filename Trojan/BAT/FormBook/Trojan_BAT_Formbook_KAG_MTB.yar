
rule Trojan_BAT_Formbook_KAG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 06 11 ?? 20 00 ?? ?? 00 5d 91 20 00 ?? 00 00 58 20 00 ?? 00 00 5d 59 d2 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
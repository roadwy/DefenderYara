
rule Trojan_BAT_Formbook_MBXM_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MBXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 07 11 09 11 0b 59 20 00 01 00 00 58 20 ff 00 00 00 5f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
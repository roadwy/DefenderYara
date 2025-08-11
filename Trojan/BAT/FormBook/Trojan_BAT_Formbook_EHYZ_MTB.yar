
rule Trojan_BAT_Formbook_EHYZ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EHYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 61 d2 13 3a 12 38 ?? ?? ?? ?? ?? 06 61 d2 13 3b 11 39 07 1f 1f 5f 62 11 39 1e 07 59 1f 1f 5f 63 60 20 ff 00 00 00 5f 13 3c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
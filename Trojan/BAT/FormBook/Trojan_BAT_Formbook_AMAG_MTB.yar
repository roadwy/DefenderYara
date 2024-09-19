
rule Trojan_BAT_Formbook_AMAG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 07 11 05 11 06 6f ?? 00 00 0a 13 07 08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 1f 61 13 0d } //2
		$a_03_1 = {08 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0f 18 91 13 0d } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
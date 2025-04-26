
rule Trojan_BAT_Formbook_MBFR_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MBFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 11 04 a2 25 17 7e ?? 00 00 0a a2 25 18 11 01 a2 25 19 17 } //1
		$a_01_1 = {37 39 66 61 34 64 62 61 2d 37 31 66 61 2d 34 37 38 30 2d 61 32 34 63 2d 62 35 34 39 33 64 32 64 36 31 61 30 } //1 79fa4dba-71fa-4780-a24c-b5493d2d61a0
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
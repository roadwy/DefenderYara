
rule Trojan_BAT_Formbook_MBCX_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MBCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6e 00 63 00 5a 00 36 00 6c 00 4d 00 51 00 2b 00 5a 00 58 00 4a 00 33 00 52 00 6a 00 51 00 75 00 2f 00 34 00 42 00 65 00 56 00 56 00 6a 00 74 00 65 00 61 00 57 00 66 00 53 00 68 00 79 00 39 00 4d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
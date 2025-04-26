
rule Trojan_BAT_Formbook_MBFU_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MBFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 00 67 00 68 00 68 00 67 00 6a 00 36 00 36 00 00 03 5c 00 00 11 56 00 62 00 6e 00 67 00 68 00 6a 00 37 00 36 } //1
		$a_01_1 = {72 00 00 05 65 00 73 00 00 05 6f 00 75 00 00 05 72 00 63 00 00 0d 39 00 30 00 75 00 6b 00 6a 00 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
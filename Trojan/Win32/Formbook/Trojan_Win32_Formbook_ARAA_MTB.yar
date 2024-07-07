
rule Trojan_Win32_Formbook_ARAA_MTB{
	meta:
		description = "Trojan:Win32/Formbook.ARAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 37 2c 02 34 69 04 0a 34 0c 2c 34 88 04 37 46 3b f3 72 eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
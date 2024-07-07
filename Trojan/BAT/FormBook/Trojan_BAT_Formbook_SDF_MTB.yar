
rule Trojan_BAT_Formbook_SDF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.SDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 07 8e 69 5d 91 13 06 08 11 05 08 8e 69 5d 91 13 07 07 11 05 07 11 05 91 11 07 61 11 06 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
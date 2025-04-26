
rule Trojan_BAT_Formbook_NM_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 38 b1 f4 ff ff 07 11 0a 91 11 07 58 13 0d 07 11 09 11 0b 11 0c 61 11 0d 11 07 5d 59 d2 9c 11 0f 20 c1 67 4b 2e 5a 20 82 fd a3 32 61 38 85 f4 ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
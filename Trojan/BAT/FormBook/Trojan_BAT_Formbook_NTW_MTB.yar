
rule Trojan_BAT_Formbook_NTW_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 15 b6 09 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 62 00 00 00 0d 00 00 00 20 00 00 00 55 00 00 00 35 00 00 00 9d 00 00 00 30 } //1
		$a_01_1 = {57 15 a2 09 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 3a 00 00 00 0b 00 00 00 0c 00 00 00 24 00 00 00 08 00 00 00 4a 00 00 00 53 00 00 00 19 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
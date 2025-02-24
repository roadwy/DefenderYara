
rule Trojan_BAT_Formbook_AMCQ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AMCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 09 } //2
		$a_01_1 = {01 25 16 11 05 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 05 1e 63 20 ff 00 00 00 5f d2 9c 25 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}

rule Trojan_BAT_Formbook_MBDB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MBDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {17 59 13 05 2b 17 00 08 07 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 26 00 11 05 17 59 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d db } //1
		$a_01_1 = {57 00 65 00 65 00 6e 00 67 00 00 35 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 00 09 4c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
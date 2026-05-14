
rule Trojan_BAT_FormBook_RVZ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RVZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 9d a2 29 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 a7 00 00 00 3c 00 00 00 ?? 01 00 00 ab 01 00 00 e1 00 00 00 78 01 00 00 03 00 00 00 24 01 00 00 0b 00 00 00 38 00 00 00 0c 00 00 00 3e 00 00 00 60 00 00 00 2b 00 00 00 0e 00 00 00 02 00 00 00 08 00 00 00 0e 00 00 00 1e 00 00 00 19 } //1
		$a_81_1 = {67 65 74 5f 53 65 72 65 6e } //1 get_Seren
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
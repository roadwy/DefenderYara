
rule Trojan_BAT_DCRat_RDD_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 74 31 45 5a 48 4a 67 66 4c 61 6f 68 44 49 53 } //1 bt1EZHJgfLaohDIS
		$a_01_1 = {6a 47 56 6a 32 } //1 jGVj2
		$a_01_2 = {4c 6f 67 69 63 61 6c 43 6f 6e 6a 75 6e 63 74 69 6f 6e } //1 LogicalConjunction
		$a_01_3 = {57 68 69 63 68 54 69 6d 65 } //1 WhichTime
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
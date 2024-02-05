
rule Trojan_BAT_DCRat_RDD_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 74 31 45 5a 48 4a 67 66 4c 61 6f 68 44 49 53 } //01 00 
		$a_01_1 = {6a 47 56 6a 32 } //01 00 
		$a_01_2 = {4c 6f 67 69 63 61 6c 43 6f 6e 6a 75 6e 63 74 69 6f 6e } //01 00 
		$a_01_3 = {57 68 69 63 68 54 69 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}
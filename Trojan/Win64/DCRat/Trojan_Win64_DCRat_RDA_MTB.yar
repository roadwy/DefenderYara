
rule Trojan_Win64_DCRat_RDA_MTB{
	meta:
		description = "Trojan:Win64/DCRat.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 61 30 37 39 31 30 33 30 2e 78 73 70 68 2e 72 75 2f 65 78 74 61 2e 65 78 65 } //01 00 
		$a_01_1 = {73 74 61 72 74 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 65 78 74 61 2e 65 78 65 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 20 62 79 20 63 6f 6e 73 74 61 6e 74 23 31 39 30 30 } //00 00 
	condition:
		any of ($a_*)
 
}
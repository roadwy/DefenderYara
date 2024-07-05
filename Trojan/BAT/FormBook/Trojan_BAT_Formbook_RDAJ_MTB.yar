
rule Trojan_BAT_Formbook_RDAJ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 6d 61 78 6c 74 6e } //01 00  Omaxltn
		$a_01_1 = {2f 00 2f 00 62 00 65 00 73 00 74 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 } //01 00  //bestsoftwaredownloads.com/panel/uploads
		$a_01_2 = {51 00 69 00 53 00 36 00 67 00 72 00 6e 00 53 00 4f 00 4c 00 54 00 49 00 67 00 51 00 56 00 35 00 33 00 6e 00 51 00 4f 00 75 00 77 00 3d 00 3d 00 } //00 00  QiS6grnSOLTIgQV53nQOuw==
	condition:
		any of ($a_*)
 
}
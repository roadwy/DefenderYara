
rule Trojan_BAT_Formbook_RPO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 00 6a 00 63 00 71 00 44 00 6f 00 77 00 57 00 6a 00 63 00 71 00 6e 00 6c 00 57 00 6a 00 63 00 71 00 6f 00 61 00 64 00 44 00 57 00 6a 00 63 00 71 00 61 00 74 00 61 00 57 00 6a 00 63 00 71 00 } //01 00  WjcqDowWjcqnlWjcqoadDWjcqataWjcq
		$a_01_1 = {32 00 30 00 2e 00 35 00 31 00 2e 00 32 00 31 00 37 00 2e 00 31 00 31 00 33 00 } //01 00  20.51.217.113
		$a_01_2 = {46 00 65 00 65 00 75 00 74 00 2e 00 6c 00 6f 00 67 00 } //01 00  Feeut.log
		$a_01_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00  powershell
		$a_01_4 = {44 00 6d 00 69 00 74 00 6d 00 7a 00 75 00 6e 00 76 00 72 00 69 00 6e 00 7a 00 6a 00 70 00 79 00 67 00 64 00 6d 00 65 00 69 00 6f 00 62 00 6d 00 } //00 00  Dmitmzunvrinzjpygdmeiobm
	condition:
		any of ($a_*)
 
}
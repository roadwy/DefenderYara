
rule Trojan_BAT_njRAT_RDR_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 36 61 30 37 61 63 39 2d 63 30 35 64 2d 34 37 34 30 2d 38 62 32 32 2d 61 66 37 62 66 37 62 34 36 33 65 37 } //01 00  26a07ac9-c05d-4740-8b22-af7bf7b463e7
		$a_01_1 = {50 72 6f 63 65 73 73 41 6e 64 52 65 67 56 61 6c } //01 00  ProcessAndRegVal
		$a_01_2 = {50 72 6f 63 65 73 73 4f 6e 6c 79 5f 43 6f 72 72 4d 5f 48 69 64 65 72 } //01 00  ProcessOnly_CorrM_Hider
		$a_01_3 = {50 72 6f 63 65 73 73 4f 6e 6c 79 20 43 6f 72 72 4d 20 48 69 64 65 72 } //00 00  ProcessOnly CorrM Hider
	condition:
		any of ($a_*)
 
}
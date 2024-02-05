
rule Trojan_BAT_QuasarRat_NEC_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {63 63 73 71 73 2e 65 78 65 } //03 00 
		$a_01_1 = {45 76 58 2e 43 6f 6d 6d 6f 6e 2e 44 4e 53 } //03 00 
		$a_01_2 = {42 65 74 74 65 72 43 61 6c 6c 2e 4d 6f 64 65 6c 73 } //03 00 
		$a_01_3 = {42 61 6e 20 53 6f 6c 75 74 69 6f 6e 73 20 32 30 32 32 } //03 00 
		$a_01_4 = {67 65 74 5f 75 70 64 61 74 65 42 61 74 } //03 00 
		$a_01_5 = {52 65 76 65 72 73 65 50 72 6f 78 79 44 69 73 63 6f 6e 6e 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_Netwire_GLB_MTB{
	meta:
		description = "Trojan:BAT/Netwire.GLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 02 00 "
		
	strings :
		$a_81_0 = {47 65 74 54 79 70 65 73 } //02 00 
		$a_81_1 = {52 65 70 6c 61 63 65 } //02 00 
		$a_81_2 = {49 44 65 66 65 72 72 65 64 } //02 00 
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //02 00 
		$a_81_4 = {48 43 56 51 75 65 73 74 69 6f 6e 6e 61 69 72 65 2e 66 72 6d 43 45 53 44 2e 72 65 73 6f 75 72 63 65 73 } //02 00 
		$a_81_5 = {54 6f 53 74 72 69 6e 67 } //02 00 
		$a_80_6 = {48 43 56 51 75 65 73 74 69 6f 6e 6e 61 69 72 65 } //HCVQuestionnaire  00 00 
	condition:
		any of ($a_*)
 
}
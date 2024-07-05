
rule Trojan_BAT_NjRat_AA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 68 6f 73 74 } //01 00  conhost
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 72 74 } //01 00  Microsofrt
		$a_01_2 = {57 69 64 6e 6f 77 73 20 70 72 6f 63 65 73 73 65 65 73 } //01 00  Widnows processees
		$a_01_3 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerStepThroughAttribute
		$a_01_4 = {00 67 16 } //00 00 
	condition:
		any of ($a_*)
 
}
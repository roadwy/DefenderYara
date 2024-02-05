
rule Trojan_Win64_Reconyc_lmnq_MTB{
	meta:
		description = "Trojan:Win64/Reconyc.lmnq!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2a a0 db df 45 f5 33 b6 90 01 04 6b e5 59 d3 e0 33 a8 90 01 04 e0 f1 64 b7 02 30 8a 90 01 04 7c e4 90 00 } //02 00 
		$a_81_1 = {73 6c 6f 61 64 65 72 2e 65 78 65 } //02 00 
		$a_81_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //00 00 
	condition:
		any of ($a_*)
 
}
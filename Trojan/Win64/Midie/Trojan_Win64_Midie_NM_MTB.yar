
rule Trojan_Win64_Midie_NM_MTB{
	meta:
		description = "Trojan:Win64/Midie.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 57 53 61 66 65 2e 70 64 62 } //02 00  RWSafe.pdb
		$a_01_1 = {47 50 54 20 31 2e 36 } //01 00  GPT 1.6
		$a_01_2 = {42 61 61 74 } //00 00  Baat
	condition:
		any of ($a_*)
 
}
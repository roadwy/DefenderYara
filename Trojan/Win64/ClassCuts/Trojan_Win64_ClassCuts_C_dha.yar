
rule Trojan_Win64_ClassCuts_C_dha{
	meta:
		description = "Trojan:Win64/ClassCuts.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_41_0 = {89 4b 68 c6 83 88 00 00 00 01 48 8b c3 48 83 c4 20 5b c3 00 } //100
	condition:
		((#a_41_0  & 1)*100) >=100
 
}
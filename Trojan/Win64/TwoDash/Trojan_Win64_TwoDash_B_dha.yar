
rule Trojan_Win64_TwoDash_B_dha{
	meta:
		description = "Trojan:Win64/TwoDash.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_41_0 = {c9 fd 43 03 00 48 8d 52 03 81 c1 c3 9e 26 00 8b c1 69 c9 fd 43 03 00 c1 e8 18 30 42 fc 81 c1 c3 9e 26 00 8b c1 69 c9 fd 43 03 00 c1 e8 18 30 42 fd 81 c1 c3 9e 26 00 8b c1 c1 e8 18 30 42 fe 49 83 e8 01 75 ba 00 } //100
	condition:
		((#a_41_0  & 1)*100) >=100
 
}
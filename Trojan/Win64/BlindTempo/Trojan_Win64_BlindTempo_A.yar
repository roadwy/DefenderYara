
rule Trojan_Win64_BlindTempo_A{
	meta:
		description = "Trojan:Win64/BlindTempo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c9 41 b8 00 10 00 00 44 8d 49 04 ff } //1
		$a_01_1 = {c7 44 24 58 73 be 47 b0 c7 44 24 5c df 70 b9 4c c7 44 24 60 c8 f3 8d 44 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
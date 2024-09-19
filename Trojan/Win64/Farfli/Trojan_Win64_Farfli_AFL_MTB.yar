
rule Trojan_Win64_Farfli_AFL_MTB{
	meta:
		description = "Trojan:Win64/Farfli.AFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 20 43 c6 44 24 21 3a c6 44 24 22 2f c6 44 24 23 55 c6 44 24 24 73 c6 44 24 25 65 c6 44 24 26 72 c6 44 24 27 73 c6 44 24 28 2f c6 44 24 29 50 c6 44 24 2a 75 c6 44 24 2b 62 c6 44 24 2c 6c c6 44 24 2d 69 c6 44 24 2e 63 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
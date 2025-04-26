
rule Trojan_Win64_TrickBot_FE_MTB{
	meta:
		description = "Trojan:Win64/TrickBot.FE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 d2 6b 6e 00 00 44 2b c2 49 63 d0 44 89 84 24 90 00 00 00 42 0f b6 04 32 43 88 44 0d 00 48 8b 44 24 28 42 88 0c 32 48 03 c2 46 0f b6 04 30 4b 8d 04 0c 42 0f b6 0c 30 b8 95 b3 61 94 44 03 c1 48 8b 8c 24 88 00 00 00 41 f7 e0 c1 ea 0e 69 d2 6b 6e 00 00 44 2b c2 49 63 c0 48 03 44 24 30 48 03 c5 48 03 c7 48 03 c6 42 0f b6 04 30 41 30 04 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
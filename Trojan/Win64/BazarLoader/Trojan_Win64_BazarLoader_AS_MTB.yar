
rule Trojan_Win64_BazarLoader_AS_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.AS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 01 6b c0 2f 83 c0 21 99 b9 7f 00 00 00 f7 f9 8b c2 48 8b 4c 24 20 88 41 0a b8 01 00 00 00 48 6b c0 0b } //1
		$a_01_1 = {0f b6 04 01 6b c0 71 83 c0 62 99 b9 7f 00 00 00 f7 f9 8b c2 48 8b 4c 24 28 88 41 01 b8 01 00 00 00 48 6b c0 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
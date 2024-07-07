
rule Trojan_Win64_Mickey_CBVV_MTB{
	meta:
		description = "Trojan:Win64/Mickey.CBVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 0b 44 c6 45 0c 41 c6 45 0d 56 c6 45 0e 58 c6 45 0f 5d c6 45 10 47 c6 45 11 5c c6 45 12 51 c6 45 13 46 c6 45 14 4b c6 45 15 46 c6 45 16 41 c6 45 17 5a c6 45 18 5a c6 45 19 51 c6 45 1a 46 c6 45 1b 34 } //1
		$a_03_1 = {0f b6 44 15 0b 8b 4d 07 32 c8 88 4c 15 0b 48 ff c2 48 83 fa 90 01 01 72 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
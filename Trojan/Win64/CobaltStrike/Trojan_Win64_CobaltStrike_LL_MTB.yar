
rule Trojan_Win64_CobaltStrike_LL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LL!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 89 c0 48 8d 15 cf 77 07 00 83 e0 0f 8a 0c 02 48 8b 44 24 48 42 32 0c 00 42 88 0c 06 49 ff c0 eb d7 } //1
		$a_01_1 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 89 cf 48 8b 58 10 48 89 de 48 8b 4b 60 48 89 fa } //1
		$a_01_2 = {0f be 11 84 d2 74 12 c1 c8 0d 80 fa 60 7e 03 83 ea 20 01 d0 48 ff c1 eb e7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
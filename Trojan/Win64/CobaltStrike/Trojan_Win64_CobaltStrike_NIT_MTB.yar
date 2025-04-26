
rule Trojan_Win64_CobaltStrike_NIT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 8d 48 1f 49 83 e1 e0 4d 8b d9 49 c1 eb 05 47 8b 9c 9a e0 c4 55 00 4d 03 da 41 ff e3 c4 a1 7e 6f 8c 0a 00 ff ff ff c4 a1 7e 7f 8c 09 00 ff ff ff c4 a1 7e 6f 8c 0a 20 ff ff ff c4 a1 7e 7f 8c 09 20 ff ff ff c4 a1 7e 6f 8c 0a 40 ff ff ff c4 a1 7e 7f 8c 09 40 ff ff ff c4 a1 7e 6f 8c 0a 60 ff ff ff c4 a1 7e 7f 8c 09 60 ff ff ff c4 a1 7e 6f 4c 0a 80 c4 a1 7e 7f 4c 09 80 c4 a1 7e 6f 4c 0a a0 c4 a1 7e 7f 4c 09 a0 c4 a1 7e 6f 4c 0a c0 c4 a1 7e 7f 4c 09 c0 c4 a1 7e 7f 6c 01 e0 c5 fe 7f 00 c5 f8 77 } //2
		$a_01_1 = {63 68 65 63 6b 69 6e 67 20 73 61 6e 64 62 6f 78 20 76 69 61 20 73 6c 65 65 70 20 74 69 6d 65 } //1 checking sandbox via sleep time
		$a_01_2 = {70 72 65 76 69 6f 75 73 6c 79 20 62 65 65 6e 20 70 6f 69 73 6f 6e 65 64 } //1 previously been poisoned
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
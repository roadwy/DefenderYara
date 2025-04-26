
rule Trojan_Win64_Kimsuky_AH_MTB{
	meta:
		description = "Trojan:Win64/Kimsuky.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 44 24 58 c6 44 24 30 aa c6 44 24 31 bb c6 44 24 32 34 c6 44 24 33 23 c6 44 24 34 a4 c6 44 24 35 c4 c6 44 24 36 c7 c6 44 24 37 dd c6 44 24 38 23 c6 44 24 39 53 c6 44 24 3a ea c6 44 24 3b a2 c6 44 24 3c 75 c6 44 24 3d 82 c6 44 24 3e e7 c6 44 24 3f 3e } //2
		$a_01_1 = {c6 44 24 46 82 c6 44 24 47 a4 c6 44 24 48 dd c6 44 24 49 1a c6 44 24 4a 3d c6 44 24 4b c2 c6 44 24 4c d2 c6 44 24 4d 62 c6 44 24 4e 28 c6 44 24 4f be c6 44 24 20 1a c6 44 24 21 b5 c6 44 24 22 3a c6 44 24 23 bb } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}

rule Trojan_Win64_Bruteratelz_A_MTB{
	meta:
		description = "Trojan:Win64/Bruteratelz.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 c0 41 80 f9 4c 75 2f 80 79 01 8b 75 29 80 79 02 d1 75 21 41 80 f8 b8 75 1b 80 79 06 00 75 17 0f b6 41 05 c1 e0 08 41 89 c0 0f b6 41 04 44 09 c0 01 d0 eb 02 31 c0 c3 } //1
		$a_01_1 = {49 89 ca 4c 89 c8 ff 64 24 28 49 89 ca 48 8b 44 24 30 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
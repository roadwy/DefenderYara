
rule Trojan_Win64_StealC_GVC_MTB{
	meta:
		description = "Trojan:Win64/StealC.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 c1 0f b6 c1 8a 84 04 90 01 00 00 48 63 4c 24 74 4d 89 f2 41 30 04 0e } //2
		$a_01_1 = {2f f2 69 c1 55 f4 c9 16 56 4b 59 8c 1e f1 00 d7 04 92 9c ee 96 83 8e 78 60 9a a2 88 05 a7 4d 9f } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}
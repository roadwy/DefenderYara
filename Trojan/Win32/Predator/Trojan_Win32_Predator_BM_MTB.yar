
rule Trojan_Win32_Predator_BM_MTB{
	meta:
		description = "Trojan:Win32/Predator.BM!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 65 6b 65 64 75 6c 65 66 75 6b 61 72 61 6e 69 63 61 79 75 70 61 6c 69 62 75 } //1 tekedulefukaranicayupalibu
		$a_01_1 = {7a 6f 74 61 79 65 6d 65 70 61 73 65 73 69 79 6f 6b 69 68 61 74 69 6e 69 } //1 zotayemepasesiyokihatini
		$a_01_2 = {b8 85 c5 0a 00 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
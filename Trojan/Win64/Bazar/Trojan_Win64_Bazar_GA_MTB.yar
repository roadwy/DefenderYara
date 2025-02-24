
rule Trojan_Win64_Bazar_GA_MTB{
	meta:
		description = "Trojan:Win64/Bazar.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 49 f7 f0 45 8a 14 11 } //1
		$a_02_1 = {44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 [0-04] 76 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
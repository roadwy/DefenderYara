
rule Trojan_Win64_ZLoader_GA_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 41 f7 f2 45 8a 1c 14 44 30 1c 0f 48 ff c1 48 89 c8 48 81 f9 ff 3f 00 00 76 e3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
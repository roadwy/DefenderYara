
rule Trojan_Win64_LazyInjector_ZZ_MTB{
	meta:
		description = "Trojan:Win64/LazyInjector.ZZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 68 44 8b 40 50 48 8b 44 24 68 48 8b 50 30 48 8b 44 24 60 48 8b 08 } //1
		$a_01_1 = {48 01 c8 48 05 08 01 00 00 48 6b 4c 24 78 28 48 01 c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
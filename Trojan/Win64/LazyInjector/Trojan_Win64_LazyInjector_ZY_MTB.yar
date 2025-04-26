
rule Trojan_Win64_LazyInjector_ZY_MTB{
	meta:
		description = "Trojan:Win64/LazyInjector.ZY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 39 95 60 05 00 00 76 28 48 8d 8d 20 01 00 00 66 90 0f b6 01 ff c2 ff c3 42 88 04 27 8b 85 60 05 00 00 48 ff c7 48 ff c1 3b d0 72 e5 85 c0 75 b1 48 8b ce ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule Trojan_Win64_RustyStealer_ZX_MTB{
	meta:
		description = "Trojan:Win64/RustyStealer.ZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 89 e0 45 21 d8 42 33 3c 82 33 79 e8 45 89 e0 41 c1 e8 18 45 89 f1 41 c1 e9 10 45 21 d9 46 8b 3c 8e 47 33 3c 82 41 89 e8 41 c1 e8 08 45 21 d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
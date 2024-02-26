
rule Trojan_Win64_CryptInject_ZZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 84 24 a0 00 00 00 e5 4e af 6a c7 84 24 b0 00 00 00 41 5f c5 17 c7 84 24 d0 00 00 00 e9 76 26 38 c7 84 24 c0 00 00 00 cb 31 44 0f c7 84 24 00 01 00 00 d6 8c 9f cc c7 84 24 f0 00 00 00 b1 48 1a a2 c7 84 24 e0 00 00 00 f1 77 7b 41 c7 84 24 10 01 00 00 a9 d0 62 c1 } //01 00 
		$a_01_1 = {53 76 63 68 6f 73 74 49 6e 6a 65 63 74 6f 72 2e 78 36 34 2e 64 6c 6c } //01 00  SvchostInjector.x64.dll
		$a_01_2 = {4d 61 70 44 4c 4c } //00 00  MapDLL
	condition:
		any of ($a_*)
 
}
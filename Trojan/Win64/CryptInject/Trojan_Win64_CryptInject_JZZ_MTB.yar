
rule Trojan_Win64_CryptInject_JZZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.JZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c1 4c 8d 05 ef 50 01 00 44 89 f8 31 d2 48 63 c9 41 f7 34 88 48 63 c2 48 8b 4d b0 32 1c 01 49 63 c7 48 8b 4d a0 88 1c 01 8b 05 e1 fa 01 00 8b 0d df fa 01 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
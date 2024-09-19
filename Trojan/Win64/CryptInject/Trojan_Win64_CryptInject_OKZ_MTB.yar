
rule Trojan_Win64_CryptInject_OKZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.OKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 ba 69 f4 26 ba 8f 41 64 e3 48 89 54 24 48 48 ba e7 c4 d7 03 6d ac 40 c9 48 89 54 24 50 31 c0 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
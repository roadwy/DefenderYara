
rule Trojan_Win64_CryptInject_AMC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.AMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 c7 c0 78 7a 93 01 48 01 e8 48 81 c0 b8 00 00 00 48 c7 c1 0b 06 00 00 48 c7 c2 b8 11 0a e8 30 10 48 ff c0 48 ff c9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
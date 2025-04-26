
rule Trojan_Win64_CryptInject_EDC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.EDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 59 41 58 5f 5e 5a 59 5b 58 5c 45 8a 14 11 44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 ff 27 00 00 0f 86 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
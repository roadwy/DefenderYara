
rule Trojan_Win64_CryptInject_DID_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.DID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c3 99 83 e2 3f 03 c2 83 e0 3f 2b c2 48 63 c8 42 8a 8c 09 50 08 06 00 43 32 8c 08 f0 7f 0c 00 48 8b 44 24 30 41 88 0c 00 ff c3 49 ff c0 48 63 c3 48 3b 84 24 18 03 00 00 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
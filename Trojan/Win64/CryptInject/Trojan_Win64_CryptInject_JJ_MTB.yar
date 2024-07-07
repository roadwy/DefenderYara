
rule Trojan_Win64_CryptInject_JJ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.JJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 39 fb 73 12 8a 14 1e 41 32 14 1c 48 ff c3 88 14 01 48 ff c0 eb e9 49 89 46 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
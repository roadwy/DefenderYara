
rule Trojan_Win64_CryptInject_KNN_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.KNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8a 14 3f 32 14 3e 88 14 39 48 ff c7 eb ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
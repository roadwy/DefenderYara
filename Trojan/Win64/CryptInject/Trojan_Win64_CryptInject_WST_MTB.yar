
rule Trojan_Win64_CryptInject_WST_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.WST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c1 46 8d 0c 48 83 e1 03 0f b6 0c 0e 32 0c 03 44 31 c9 88 0c 03 48 83 c0 01 48 39 c2 75 e0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
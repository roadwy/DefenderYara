
rule Trojan_Win64_CryptInject_IN_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.IN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 44 38 c0 74 ?? 44 31 c0 88 01 32 02 88 02 32 01 f7 d0 48 83 c1 ?? 88 41 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
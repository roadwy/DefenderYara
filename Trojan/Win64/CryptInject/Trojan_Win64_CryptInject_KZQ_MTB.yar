
rule Trojan_Win64_CryptInject_KZQ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.KZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 8a d6 e8 ?? ?? ?? ?? 40 0f b6 ce 48 c1 e9 04 0f b6 d0 c1 e8 04 83 e2 0f 48 33 d1 8b 0c 93 33 c8 85 ff 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
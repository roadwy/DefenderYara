
rule Trojan_Win64_CryptInject_MXD_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 3b 41 0f b6 c0 2a c1 04 3a 41 32 01 34 39 41 88 01 41 ff c0 4d 8d 49 01 41 83 f8 0e 7c cb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
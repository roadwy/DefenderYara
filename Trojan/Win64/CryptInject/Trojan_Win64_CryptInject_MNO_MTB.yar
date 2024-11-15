
rule Trojan_Win64_CryptInject_MNO_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 0f b6 9c 1c a0 00 00 00 42 30 1c 1f 49 ff c3 4c 39 d9 75 eb 4a 8d 0c 1f e9 be 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
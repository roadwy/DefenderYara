
rule Trojan_Win64_CryptInject_MQH_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MQH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 29 c6 49 63 de 48 8d 14 1c 48 81 c2 70 01 00 00 e8 ?? ?? ?? ?? 0f b6 84 3c 70 01 00 00 0f b6 8c 1c 70 01 00 00 01 c1 0f b6 c1 0f b6 84 04 70 01 00 00 48 63 4c 24 64 30 04 0e 8b 7c 24 64 83 c7 01 b8 c4 d5 1f d7 3d bb 36 00 07 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
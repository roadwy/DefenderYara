
rule Trojan_Win64_CryptInject_WSZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.WSZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b d8 48 2b d8 49 63 ca 48 b8 5f 43 79 0d ?? ?? ?? ?? 45 03 d4 48 f7 e1 48 c1 ea 04 48 6b c2 13 48 2b c8 48 0f af ce 8a 44 0c ?? 42 32 04 1b 41 88 03 4d 03 dc 41 81 fa c1 e0 01 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
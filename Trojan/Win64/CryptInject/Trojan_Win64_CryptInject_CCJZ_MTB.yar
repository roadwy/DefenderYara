
rule Trojan_Win64_CryptInject_CCJZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.CCJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 48 83 ec 20 41 8b d9 49 8b f8 48 8b f2 48 8b e9 e8 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? 45 33 c0 ba 01 00 00 00 48 8d 81 ?? ?? ?? ?? ff d0 48 8b 05 ?? ?? ?? ?? 44 8b cb 48 05 ?? ?? ?? ?? 4c 8b c7 48 8b d6 48 8b cd 48 8b 5c 24 30 48 8b 6c 24 38 48 8b 74 24 40 48 83 c4 20 5f 48 ff e0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
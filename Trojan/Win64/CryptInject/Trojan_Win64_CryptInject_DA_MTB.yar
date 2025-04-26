
rule Trojan_Win64_CryptInject_DA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 08 57 48 83 ec 20 48 63 da 48 8b f9 ba 01 00 00 00 48 8b cb ff 15 ?? ?? ?? ?? 33 d2 48 3b da 7e ?? 8a 0c 97 80 f1 4b 88 0c 02 48 ff c2 48 3b d3 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CryptInject_DA_MTB_2{
	meta:
		description = "Trojan:Win64/CryptInject.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 fe c1 49 ff c3 45 0f b6 c9 42 8b 7c 8e ?? 44 02 d7 45 0f b6 d2 42 8b 4c 96 ?? 42 89 4c 8e ?? 40 02 cf 42 89 7c 96 ?? 0f b6 c1 0f b6 4c 86 ?? 41 30 4b ?? 48 ff cb 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CryptInject_DA_MTB_3{
	meta:
		description = "Trojan:Win64/CryptInject.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 8b d8 8b c3 41 2b c3 66 89 44 24 ?? 8b 44 24 ?? 83 c0 ?? 89 44 24 ?? 0f b7 54 24 ?? 8b 44 24 ?? c1 e8 ?? 8b 4c 24 ?? c1 e1 ?? 0b c1 8b ca 03 c8 8b 44 24 ?? 33 c1 89 44 24 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
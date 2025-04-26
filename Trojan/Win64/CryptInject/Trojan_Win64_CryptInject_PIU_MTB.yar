
rule Trojan_Win64_CryptInject_PIU_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.PIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 29 c0 48 8d 45 dc 4c 33 45 f7 48 31 55 f4 b9 6f e8 00 00 89 45 e8 4c 89 55 d4 89 c2 49 89 d2 4c 03 45 ef 05 fc db 00 00 2b 4d e8 48 8b 4d ec 8b 4d f6 49 c7 c0 ?? ?? 00 00 01 c1 4c 89 55 d8 01 c9 89 55 f1 48 ff 04 24 49 c7 c2 05 00 00 00 4c 39 14 24 0f 8e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
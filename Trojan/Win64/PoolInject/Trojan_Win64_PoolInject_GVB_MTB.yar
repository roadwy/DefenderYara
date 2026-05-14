
rule Trojan_Win64_PoolInject_GVB_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 01 f3 48 83 c7 08 ff 15 68 1c 00 00 48 95 8a 07 48 ff c7 08 c0 74 d7 79 0a 48 0f b7 17 48 83 c7 02 eb 0a 48 89 f9 48 89 fa ff c8 f2 ae 48 89 e9 ff 15 4e 1c 00 00 48 09 c0 74 09 48 89 03 48 83 c3 08 eb ca } //2
		$a_01_1 = {48 89 4c 24 08 48 83 ec 28 e8 12 27 1a 00 83 e0 01 89 44 24 38 8b 44 24 38 b9 0d f0 ad ba ba ef be ad de 85 c0 0f 45 ca 48 89 4c 24 38 4c 8b 44 24 38 41 c7 00 7b 00 00 00 41 8b 00 05 c8 01 00 00 89 44 24 38 8b 44 24 38 85 c0 7e 0d } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
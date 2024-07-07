
rule Trojan_Win32_NSISInject_SMTK_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SMTK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 05 00 00 43 00 88 45 f7 8b 45 ec 8b 4d f0 8a 04 08 88 45 f6 0f b6 45 f7 c1 f8 03 0f b6 4d f7 c1 e1 05 09 c8 0f b6 4d f6 31 c8 88 c1 8b 45 f8 88 0c 05 00 00 43 00 8b 45 f0 83 c0 01 b9 0d 00 00 00 99 f7 f9 89 55 f0 8b 45 f8 83 c0 01 89 45 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_NSISInject_SMTK_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.SMTK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 85 23 e2 ff ff c1 f8 03 0f b6 8d 23 e2 ff ff c1 e1 05 09 c8 0f b6 8d 22 e2 ff ff 31 c8 88 c1 8b 85 24 e2 ff ff 88 8c 05 2b e2 ff ff 8b 85 1c e2 ff ff 83 c0 01 b9 0d 00 00 00 99 f7 f9 89 95 1c e2 ff ff 8b 85 24 e2 ff ff 83 c0 01 89 85 24 e2 ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
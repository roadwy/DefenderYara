
rule Trojan_Win64_PoolInject_SXE_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.SXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b c2 48 c1 e8 3e 48 33 d0 49 0f af d0 48 03 d1 48 89 94 cc c0 00 00 00 48 ff c1 48 81 f9 38 01 00 00 72 db } //30
		$a_01_1 = {4c 8b 75 c8 49 c1 e6 04 4d 03 f0 48 ff 45 c8 41 0f b6 06 ff c8 83 f8 0f } //10
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*10) >=40
 
}
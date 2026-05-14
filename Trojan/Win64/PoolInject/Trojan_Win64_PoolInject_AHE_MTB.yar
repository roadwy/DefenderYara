
rule Trojan_Win64_PoolInject_AHE_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 0f b6 0c 24 48 8b 54 24 08 0f b6 04 02 33 c1 8b 4c 24 04 48 8b 54 24 08 88 04 0a e9 } //30
		$a_01_1 = {c7 45 f0 4c 6f 61 64 c7 45 f4 4c 69 62 72 c7 45 f8 61 72 79 41 c6 45 fc 00 } //20
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}
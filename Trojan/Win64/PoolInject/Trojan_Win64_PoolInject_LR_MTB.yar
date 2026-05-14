
rule Trojan_Win64_PoolInject_LR_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 00 48 83 c0 20 48 89 84 24 d0 00 00 00 48 8b 84 24 d0 00 00 00 8b 00 ff c0 48 8b 8c 24 d0 00 00 00 89 01 33 c0 85 c0 } //20
		$a_01_1 = {33 c9 48 6b c9 08 48 03 48 08 48 8b c1 48 89 84 24 88 00 00 00 48 8b 84 24 88 00 00 00 48 8b 00 48 89 84 24 c8 00 00 00 33 d2 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
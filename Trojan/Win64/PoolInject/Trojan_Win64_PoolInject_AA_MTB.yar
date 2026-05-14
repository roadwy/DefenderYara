
rule Trojan_Win64_PoolInject_AA_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 28 84 24 80 00 00 00 0f 28 4c 24 30 66 0f ef c8 0f 29 4c 24 30 48 8d 44 24 30 48 89 84 24 c0 } //30
		$a_03_1 = {48 31 d1 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 31 d1 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 01 d1 48 89 c2 48 01 ca 48 89 54 24 28 } //20
	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}

rule Trojan_Win64_PoolInject_GVA_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {4c 8b 00 41 0f b6 81 ?? ?? ?? ?? 42 0f b6 14 0a 42 32 14 08 43 30 14 10 49 ff c2 48 8b 41 08 4c 3b 10 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
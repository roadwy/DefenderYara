
rule Trojan_Win64_PoolInject_BR_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 33 ca 49 c1 e1 20 4c 0b c9 49 8b c9 45 88 0c 03 48 c1 e9 08 41 88 4c 03 01 } //2
		$a_01_1 = {0f b6 0c 2f 4c 8d 1c 2f 45 0f b6 4b 01 49 c1 e1 08 4c 0b c9 } //2
		$a_03_2 = {45 88 4c 03 ?? 41 88 4c 03 ?? 48 83 c7 08 48 81 ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1) >=5
 
}
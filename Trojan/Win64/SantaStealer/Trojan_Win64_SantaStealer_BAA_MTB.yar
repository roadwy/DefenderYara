
rule Trojan_Win64_SantaStealer_BAA_MTB{
	meta:
		description = "Trojan:Win64/SantaStealer.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 72 f0 19 66 0f eb c3 66 0f 6f da 66 0f 72 f3 0e 66 0f 72 d2 03 66 0f eb dc 66 0f ef c3 66 0f ef c2 f3 0f 7e 50 b8 66 0f fe c8 f3 0f 7e 40 dc 66 0f fe c2 66 0f fe c1 66 0f d6 40 f8 48 39 c6 0f 85 59 ff ff ff } //2
		$a_01_1 = {8b 84 24 68 01 00 00 48 83 c6 01 0f b6 0e 8d 50 01 48 83 c3 08 89 94 24 68 01 00 00 88 8c 04 20 01 00 00 48 89 9c 24 60 01 00 00 83 fa 40 74 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
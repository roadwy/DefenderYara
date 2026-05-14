
rule Trojan_Win64_PoolInject_KK_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 48 8d 0d ?? ?? ?? ?? ?? ?? ?? 00 00 48 8b 00 48 83 c0 20 48 89 44 24 60 48 8b 44 24 60 8b 00 ff c0 48 8b 4c 24 60 89 01 33 c0 85 c0 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}
rule Trojan_Win64_PoolInject_KK_MTB_2{
	meta:
		description = "Trojan:Win64/PoolInject.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 4b 10 48 89 4b 28 89 4b 30 48 89 4b 38 89 4b 40 48 89 4b 48 89 4b 50 48 89 4b 58 48 89 43 60 89 4b 18 } //20
		$a_03_1 = {33 d2 0f be 0d ?? ?? ?? 00 03 c5 03 c6 f7 f1 0f be 0d ?? ?? ?? 00 2b c1 0f af c7 85 c0 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}
rule Trojan_Win64_PoolInject_KK_MTB_3{
	meta:
		description = "Trojan:Win64/PoolInject.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 85 88 00 00 00 2f c6 85 89 00 00 00 63 c6 85 8a 00 00 00 20 c6 85 8b 00 00 00 74 c6 85 8c 00 00 00 69 c6 85 8d 00 00 00 6d c6 85 8e 00 00 00 65 c6 85 8f 00 00 00 6f c6 85 90 00 00 00 75 c6 85 91 00 00 00 74 c6 85 92 00 00 00 20 c6 85 93 00 00 00 35 c6 85 94 00 00 00 20 c6 85 95 00 00 00 26 c6 85 96 00 00 00 20 c6 85 97 00 00 00 22 c6 85 98 00 00 00 25 c6 85 99 00 00 00 73 c6 85 9a 00 00 00 22 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}
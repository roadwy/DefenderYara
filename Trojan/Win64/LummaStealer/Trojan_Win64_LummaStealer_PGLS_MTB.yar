
rule Trojan_Win64_LummaStealer_PGLS_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f8 c1 e8 0d 31 f8 69 c0 ?? ?? ?? ?? 89 c6 c1 ee ?? 31 c6 48 8b 4c 24 ?? 48 31 e1 e8 ?? ?? ?? ?? 89 f0 48 83 c4 ?? 5b 5d 5f 5e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_LummaStealer_PGLS_MTB_2{
	meta:
		description = "Trojan:Win64/LummaStealer.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 0f b6 84 04 ?? ?? ?? ?? 48 63 4c 24 ?? 48 8b 54 24 ?? 30 04 0a 8b 7c 24 ?? 83 c7 01 b8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 8f ?? ?? ?? ?? e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_LummaStealer_PGLS_MTB_3{
	meta:
		description = "Trojan:Win64/LummaStealer.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 44 24 ?? 48 8b 4c 24 20 69 04 81 95 e9 d1 5b 89 c1 c1 e9 ?? 31 c1 69 c1 95 e9 d1 5b 69 5c 24 ?? 95 e9 d1 5b 31 c3 8b 6c 24 ?? 83 c5 ?? 41 ba ?? ?? ?? ?? 41 81 fa ?? ?? ?? ?? 0f 8f ?? ?? ?? ?? e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_LummaStealer_PGLS_MTB_4{
	meta:
		description = "Trojan:Win64/LummaStealer.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 48 8b 4d ?? 0f b6 04 01 48 63 4d ?? 41 30 04 0e 44 8b 75 ?? 41 83 c6 01 b8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 8f } //5
		$a_03_1 = {01 c1 0f b6 c1 0f b6 84 04 ?? ?? ?? ?? 48 63 4c 24 ?? 48 8b 54 24 ?? 30 04 0a 8b 74 24 ?? 83 c6 01 b8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}

rule Trojan_Win64_Rozena_NM_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 15 e8 a9 02 03 00 48 8b 44 24 ?? 49 89 03 48 8b 4a ?? 49 89 4b 08 48 89 42 ?? 48 c7 42 18 ?? ?? ?? ?? 48 83 c4 18 } //3
		$a_03_1 = {48 89 44 24 ?? 48 89 5c 24 ?? e8 78 e3 02 00 48 8b 44 24 ?? 48 8b 5c 24 ?? e9 69 ff ff ff } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win64_Rozena_NM_MTB_2{
	meta:
		description = "Trojan:Win64/Rozena.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 e8 cf 07 ?? ?? 85 c0 74 21 65 48 8b 04 25 30 00 00 00 48 8b 48 08 eb ?? 48 3b c8 74 ?? 33 c0 f0 48 0f b1 0d 34 97 01 00 75 ?? 32 c0 48 83 } //3
		$a_03_1 = {40 53 48 83 ec 20 80 3d e4 96 01 00 00 8b d9 75 ?? 83 f9 01 77 ?? e8 45 07 00 00 85 c0 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}
rule Trojan_Win64_Rozena_NM_MTB_3{
	meta:
		description = "Trojan:Win64/Rozena.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 45 33 c0 ba ?? ?? ?? ?? 48 8b c8 e8 6d 15 f3 ff 48 8b 44 24 } //2
		$a_03_1 = {eb 0a 8b 44 24 30 ff c0 89 44 24 ?? 48 63 44 24 ?? 48 83 f8 05 73 11 48 63 44 24 ?? 48 8b 4c 24 ?? c6 44 01 3e 00 eb da e9 fa fe ff ff 48 8d 4c 24 ?? e8 50 18 f3 ff 48 89 44 24 ?? 48 8d 4c 24 ?? e8 16 fd f2 ff } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}
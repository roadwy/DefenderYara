
rule Trojan_Win64_Rozena_NR_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d da fd ff ff 48 89 02 e8 da 40 00 00 e8 4d 36 00 00 48 63 1d ?? ?? ?? ?? 8d 4b 01 48 63 c9 } //3
		$a_03_1 = {48 c1 e1 03 e8 6f 41 00 00 4c 8b 35 ?? ?? ?? ?? 49 89 c5 44 39 e3 7e 2b 4b 8b 0c e6 e8 6f 41 00 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win64_Rozena_NR_MTB_2{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 5d 2c ff ff 48 89 6b ?? 48 8b 2d 52 40 01 00 41 bb ?? ?? ?? ?? 4c 89 23 4c } //3
		$a_03_1 = {45 31 c0 4c 89 e1 48 8b 05 f9 41 01 00 66 44 89 87 ?? ?? ?? ?? 48 c7 87 e8 00 00 00 ?? ?? ?? ?? 48 8d 50 18 48 83 c0 40 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win64_Rozena_NR_MTB_3{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d c3 99 12 00 48 8b 01 48 05 ?? ?? ?? ?? 48 89 41 10 48 89 41 18 } //3
		$a_03_1 = {48 8d 3d 63 9f 12 00 e8 c6 3f 00 00 65 48 8b 1c 25 ?? ?? ?? ?? 48 c7 83 00 00 00 00 23 01 00 00 48 8b 05 ?? ?? ?? ?? 48 3d 23 01 00 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win64_Rozena_NR_MTB_4{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 35 7b e0 55 00 65 48 8b 04 25 30 00 00 00 48 8b 58 08 31 c0 f0 48 0f b1 5d 00 74 ?? 48 39 c3 74 ?? b9 e8 03 00 00 } //3
		$a_03_1 = {8d 4b 01 48 63 c9 48 c1 e1 03 e8 ?? ?? ?? ?? 4c 8b 35 d0 bd 55 00 49 89 c5 44 39 e3 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}
rule Trojan_Win64_Rozena_NR_MTB_5{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 20 48 8d 05 7d 71 1c 00 e8 ?? ?? ?? ?? 48 8b 4c 24 10 48 89 08 48 8b 4c 24 20 48 8b 11 48 89 50 10 48 89 01 } //3
		$a_01_1 = {48 8d 15 1d 7b 0c 00 48 89 c6 48 8b 44 24 40 48 89 df 48 89 f3 49 89 c8 48 89 f9 41 ff d0 48 8b 4c 24 40 48 8d 14 49 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win64_Rozena_NR_MTB_6{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 33 66 0f 6f 05 ?? ?? ?? ?? 48 83 c8 ff f3 0f 7f 05 ?? ?? ?? ?? 48 89 05 0e cf 94 00 f3 0f 7f 05 ?? ?? ?? ?? 48 89 05 17 cf 94 } //5
		$a_01_1 = {73 74 65 61 6d 5f 6d 6f 64 75 6c 65 5f 78 36 34 2e 70 64 62 } //1 steam_module_x64.pdb
		$a_01_2 = {70 72 69 6d 6f 72 64 69 61 6c 5f 63 72 61 63 6b } //1 primordial_crack
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_Win64_Rozena_NR_MTB_7{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d0 85 c0 75 07 b8 ff ff ff ff eb 75 48 8b 4d ?? 48 8d 45 ?? 48 89 44 24 ?? 48 8b 45 ?? 48 89 44 24 ?? 41 b9 00 00 00 00 41 b8 00 00 00 00 ba } //3
		$a_03_1 = {e9 a8 00 00 00 48 8b 55 ?? 48 8b 4d ?? 48 8d 45 ?? 48 89 44 24 ?? 41 b9 00 00 00 00 49 89 d0 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}
rule Trojan_Win64_Rozena_NR_MTB_8{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 15 6b 22 00 00 ff 15 95 20 00 00 b9 ?? ?? 00 00 66 89 bd ?? ?? 00 00 ff 15 7b 20 00 00 44 8d 47 0e 48 8b cb 48 8d 95 ?? ?? 00 00 66 89 85 ?? ?? 00 00 ff 15 80 20 00 00 } //3
		$a_03_1 = {ff 15 cd 1d 00 00 48 89 74 24 ?? 4c 8b cb 89 74 24 ?? 45 33 c0 33 d2 48 89 74 24 ?? 48 8b cf ff 15 c6 1d 00 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
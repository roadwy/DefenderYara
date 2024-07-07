
rule Trojan_Win64_Rozena_NR_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d da fd ff ff 48 89 02 e8 da 40 00 00 e8 4d 36 00 00 48 63 1d 90 01 04 8d 4b 01 48 63 c9 90 00 } //3
		$a_03_1 = {48 c1 e1 03 e8 6f 41 00 00 4c 8b 35 90 01 04 49 89 c5 44 39 e3 7e 2b 4b 8b 0c e6 e8 6f 41 00 00 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win64_Rozena_NR_MTB_2{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 5d 2c ff ff 48 89 6b 90 01 01 48 8b 2d 52 40 01 00 41 bb 90 01 04 4c 89 23 4c 90 00 } //3
		$a_03_1 = {45 31 c0 4c 89 e1 48 8b 05 f9 41 01 00 66 44 89 87 90 01 04 48 c7 87 e8 00 00 00 90 01 04 48 8d 50 18 48 83 c0 40 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win64_Rozena_NR_MTB_3{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d c3 99 12 00 48 8b 01 48 05 90 01 04 48 89 41 10 48 89 41 18 90 00 } //3
		$a_03_1 = {48 8d 3d 63 9f 12 00 e8 c6 3f 00 00 65 48 8b 1c 25 90 01 04 48 c7 83 00 00 00 00 23 01 00 00 48 8b 05 90 01 04 48 3d 23 01 00 00 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win64_Rozena_NR_MTB_4{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 33 66 0f 6f 05 90 01 04 48 83 c8 ff f3 0f 7f 05 90 01 04 48 89 05 0e cf 94 00 f3 0f 7f 05 90 01 04 48 89 05 17 cf 94 90 00 } //5
		$a_01_1 = {73 74 65 61 6d 5f 6d 6f 64 75 6c 65 5f 78 36 34 2e 70 64 62 } //1 steam_module_x64.pdb
		$a_01_2 = {70 72 69 6d 6f 72 64 69 61 6c 5f 63 72 61 63 6b } //1 primordial_crack
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
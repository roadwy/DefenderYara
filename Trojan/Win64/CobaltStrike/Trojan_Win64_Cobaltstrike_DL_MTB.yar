
rule Trojan_Win64_Cobaltstrike_DL_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 c9 4d 8d 40 01 49 83 fa 15 49 0f 45 ca 41 ff c1 42 0f b6 04 19 4c 8d 51 01 41 30 40 ff 41 81 f9 cc 01 00 00 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Cobaltstrike_DL_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {50 c7 44 24 04 00 00 00 00 b8 90 5f 01 00 48 03 05 da 2f 00 00 41 5a 48 ff e0 } //05 00 
		$a_00_1 = {33 65 33 6d 31 6c 30 65 30 65 30 67 30 68 30 69 30 66 30 6b 30 6c 30 6d 30 6e 30 6f 30 70 30 71 30 72 31 63 31 64 31 } //03 00  3e3m1l0e0e0g0h0i0f0k0l0m0n0o0p0q0r1c1d1
		$a_80_2 = {52 65 74 70 6f 6c 69 6e 65 } //Retpoline  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Cobaltstrike_DL_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 29 c0 8b 05 90 01 04 41 29 c0 8b 05 90 01 04 41 29 c0 8b 05 90 01 04 41 29 c0 44 89 c0 4c 63 c0 48 8b 45 90 01 01 4c 01 c0 0f b6 00 31 c8 88 02 83 45 90 01 02 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //01 00 
		$a_81_1 = {6e 25 72 21 77 3f 24 2b 4f 56 77 64 76 68 35 37 24 37 41 40 33 31 54 2b 4b 4f 36 6a 4a 73 21 69 32 72 66 23 53 3c 76 6b 5e 5a 44 6a 5a 35 56 32 69 4d 33 25 6f 34 51 32 3c 36 2b 44 28 47 } //00 00  n%r!w?$+OVwdvh57$7A@31T+KO6jJs!i2rf#S<vk^ZDjZ5V2iM3%o4Q2<6+D(G
	condition:
		any of ($a_*)
 
}
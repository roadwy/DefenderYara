
rule Trojan_Win64_StrelaStealer_ASL_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 10 48 89 7c 24 20 31 c9 ba 1a 00 00 00 45 31 c0 45 31 c9 4c 8b 25 06 28 05 00 41 ff d4 48 83 c4 10 48 89 f9 4c 8d 3d 2b f6 04 00 4c 89 fa 4c 89 eb 41 ff d5 41 b8 04 01 00 00 48 89 f1 31 d2 e8 14 93 04 00 } //2
		$a_01_1 = {63 38 64 37 39 64 35 35 2d 36 37 32 33 2d 34 64 38 35 2d 39 66 32 33 2d 37 32 35 32 65 32 65 32 62 66 66 31 } //1 c8d79d55-6723-4d85-9f23-7252e2e2bff1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win64_StrelaStealer_ASL_MTB_2{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {ff 03 00 00 0f b6 ?? ?? 04 32 ?? ?? 04 04 00 00 80 f2 0c 88 ?? 3d 04 04 00 00 48 83 ?? 01 48 39 ?? 72 } //4
		$a_03_1 = {ff 03 00 00 0f b6 ?? ?? 04 32 ?? ?? 04 04 00 00 34 0c 88 84 ?? 04 04 00 00 48 83 c1 01 4c 39 ?? 72 } //4
		$a_03_2 = {ff 03 00 00 42 0f b6 4c ?? 04 42 32 8c ?? 04 04 00 00 80 f1 0c 42 88 8c ?? 04 04 00 00 48 83 c5 01 84 d2 75 } //4
		$a_01_3 = {0f b6 5c 03 04 41 32 9c 03 05 04 00 00 80 f3 0c 41 88 9c 03 05 04 00 00 49 83 c3 02 4d 39 dc 75 } //4
		$a_01_4 = {65 6e 74 72 79 } //1 entry
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_03_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*1) >=5
 
}
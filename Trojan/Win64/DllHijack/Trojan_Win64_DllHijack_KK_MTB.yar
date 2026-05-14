
rule Trojan_Win64_DllHijack_KK_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b d1 4c 8d 44 17 10 0f b6 54 10 10 41 30 10 ff c1 44 3b f1 7f ea } //20
		$a_03_1 = {8b c6 48 0f af c8 48 c1 e9 ?? 6b c9 ?? 44 8b f6 44 2b f1 41 83 fe } //10
		$a_03_2 = {8b c7 48 0f af c8 48 c1 e9 ?? 6b c9 ?? 44 8b f7 44 2b f1 41 83 fe } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=30
 
}
rule Trojan_Win64_DllHijack_KK_MTB_2{
	meta:
		description = "Trojan:Win64/DllHijack.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 8b ca 46 0f b6 04 49 41 8d 50 9f 80 fa 19 41 8d 40 e0 0f b6 c8 41 0f 47 c8 41 ff c2 42 88 8c ?? ?? ?? 00 00 49 8b 4b 50 66 } //20
		$a_01_1 = {8d 42 01 0f b6 d0 4d 8d 5b 01 0f b6 0c 14 8d 04 0b 0f b6 d8 0f b6 04 1c 88 04 14 88 0c 1c 0f b6 04 14 48 03 c8 0f b6 c1 0f b6 0c 04 41 30 4b ff 49 83 e8 01 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
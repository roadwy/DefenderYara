
rule Trojan_BAT_ClipBanker_AYB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {02 07 8f 48 00 00 01 25 47 06 07 06 8e 69 5d 91 61 d2 52 07 17 58 0b 07 02 8e 69 32 e3 } //8
		$a_01_1 = {73 74 75 62 2e 70 64 62 } //2 stub.pdb
		$a_01_2 = {58 6f 72 45 6e 63 72 79 70 74 4d 79 4b 65 79 } //1 XorEncryptMyKey
		$a_01_3 = {47 65 74 52 61 6e 64 6f 6d 4c 65 67 69 74 69 6d 61 74 65 54 61 73 6b 4e 61 6d 65 } //1 GetRandomLegitimateTaskName
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}
rule Trojan_BAT_ClipBanker_AYB_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 07 19 11 07 19 95 09 19 95 61 9e 11 07 1a 11 07 1a 95 09 1a 95 61 9e 11 0d 20 ee f7 c0 8c 5a 20 57 4b 50 4b 61 } //10
		$a_01_1 = {11 07 1d 11 07 1d 95 09 1d 95 61 9e 11 07 1e 11 07 1e 95 09 1e 95 61 9e 11 0d 20 76 a6 03 bb 5a 20 73 f8 68 0d 61 } //10
		$a_01_2 = {24 64 62 66 64 33 36 63 64 2d 65 61 38 63 2d 34 31 36 64 2d 39 61 35 39 2d 62 33 32 61 30 63 32 33 65 35 65 39 } //1 $dbfd36cd-ea8c-416d-9a59-b32a0c23e5e9
		$a_01_3 = {79 75 64 62 74 6d 75 64 77 68 2e 52 65 73 6f 75 72 63 65 73 } //1 yudbtmudwh.Resources
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}
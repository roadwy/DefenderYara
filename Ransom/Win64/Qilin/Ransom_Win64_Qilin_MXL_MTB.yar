
rule Ransom_Win64_Qilin_MXL_MTB{
	meta:
		description = "Ransom:Win64/Qilin.MXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {89 d0 83 c2 01 48 83 c1 01 83 e0 1f 0f b6 44 04 50 32 41 ff f7 d0 c0 c0 04 88 41 ff 81 fa 00 02 00 00 75 dc } //5
		$a_81_1 = {48 61 6c 6f 21 20 46 69 6c 65 20 41 6e 64 61 20 62 61 72 75 20 73 61 6a 61 20 74 69 64 61 6b 20 74 65 72 73 65 64 69 61 } //1 Halo! File Anda baru saja tidak tersedia
		$a_81_2 = {53 49 53 54 45 4d 20 44 49 4b 4f 4d 50 52 4f 4d 49 4b 41 4e } //1 SISTEM DIKOMPROMIKAN
		$a_81_3 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
		$a_81_4 = {44 69 73 61 62 6c 65 42 65 68 61 76 69 6f 72 4d 6f 6e 69 74 6f 72 69 6e 67 } //1 DisableBehaviorMonitoring
		$a_81_5 = {65 6e 63 72 79 70 74 65 64 2e 64 61 74 61 } //1 encrypted.data
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=10
 
}
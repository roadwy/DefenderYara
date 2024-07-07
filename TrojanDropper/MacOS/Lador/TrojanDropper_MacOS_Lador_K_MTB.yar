
rule TrojanDropper_MacOS_Lador_K_MTB{
	meta:
		description = "TrojanDropper:MacOS/Lador.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {65 48 8b 0c 25 30 00 00 00 48 3b 61 10 0f 86 e3 03 00 00 48 83 ec 38 48 89 6c 24 30 48 8d 6c 24 30 48 8d 05 98 4d 31 00 48 89 04 24 e8 0f d6 00 00 48 8b 7c 24 08 48 89 7c 24 28 48 8d 35 be ce 3e 00 48 89 6c 24 f0 48 8d 6c 24 f0 e8 eb 8e 06 00 48 8b 6d 00 83 3d 14 89 5e 00 00 0f 1f 40 00 0f 85 70 02 00 00 48 8d 05 34 8d 5e 00 48 8b 4c 24 28 48 89 41 10 48 8d 05 23 8d 5e 00 48 89 41 30 48 8d 05 1a 8d 5e 00 48 89 41 50 48 8d 05 10 8d 5e 00 48 89 41 70 48 8d 05 06 8d 5e 00 48 89 81 90 00 00 00 48 8d 05 f9 8c 5e 00 } //2
		$a_00_1 = {49 89 c6 48 89 c7 e8 c1 27 3f 00 be 00 01 00 08 48 89 c7 e8 ba 27 3f 00 48 89 c3 48 ff c3 48 89 df e8 b2 27 3f 00 49 89 c4 b9 00 01 00 08 4c 89 f7 48 89 c6 48 89 da e8 a2 27 3f 00 84 c0 74 1e 48 8b 05 55 48 57 00 48 8b 38 31 c0 48 8d 35 62 dd 3e 00 4c 89 e2 44 89 e9 } //2
		$a_00_2 = {64 65 6e 69 73 62 72 6f 64 62 65 63 6b 2f 6d 61 63 68 69 6e 65 69 64 2e 65 78 74 72 61 63 74 69 64 } //1 denisbrodbeck/machineid.extractid
		$a_00_3 = {49 4f 50 6c 61 74 66 6f 72 6d 45 78 70 65 72 74 44 65 76 69 63 65 } //1 IOPlatformExpertDevice
		$a_00_4 = {72 75 6e 74 69 6d 65 2e 70 65 72 73 69 73 74 65 6e 74 61 6c 6c 6f 63 } //1 runtime.persistentalloc
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}
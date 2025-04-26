
rule Trojan_Win64_IcedID_EG_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 2b 00 00 00 83 c0 3d 66 3b e4 74 0e 48 83 ec 58 b8 16 00 00 00 66 3b c9 74 0f 66 89 44 24 2a b8 3f 00 00 00 66 3b c9 74 49 83 c0 3d 66 89 44 24 28 66 3b c9 74 c9 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win64_IcedID_EG_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 c1 e0 ?? 01 d0 c1 e0 ?? 29 c1 89 ca 48 63 d2 48 8b 85 ?? ?? ?? ?? 48 01 d0 0f b6 00 44 31 c8 41 88 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_IcedID_EG_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 3a e4 74 d6 b8 4d 00 00 00 83 c0 18 66 3b d2 74 00 66 89 44 24 52 b8 45 00 00 00 66 3b d2 74 35 } //3
		$a_01_1 = {75 69 73 62 61 64 79 75 67 61 75 73 62 64 6a 61 73 79 75 64 6a 61 73 } //1 uisbadyugausbdjasyudjas
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_Win64_IcedID_EG_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 69 66 6e 79 61 73 66 62 6a 61 75 69 6e 79 75 67 61 73 6a 61 73 } //1 uifnyasfbjauinyugasjas
		$a_01_1 = {64 00 65 00 74 00 79 00 35 00 74 00 70 00 65 00 32 00 52 00 66 00 62 00 6a 00 69 00 68 00 65 00 72 00 61 00 67 00 65 00 } //1 dety5tpe2Rfbjiherage
		$a_01_2 = {52 65 6c 65 61 73 65 53 65 6d 61 70 68 6f 72 65 } //1 ReleaseSemaphore
		$a_01_3 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //1 CreateMutexW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
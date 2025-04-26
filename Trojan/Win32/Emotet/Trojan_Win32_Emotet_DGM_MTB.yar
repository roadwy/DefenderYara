
rule Trojan_Win32_Emotet_DGM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {33 d2 b9 b0 ff 00 00 f7 f1 56 56 8b ca 8a 5c 0c 30 0f b6 c3 03 c7 33 d2 bf b0 ff 00 00 f7 f7 } //1
		$a_81_1 = {23 4b 61 6d 53 36 54 47 4e 43 66 56 52 30 33 4b 7b 47 79 4f 39 5a 7c 6e 34 78 6a 31 24 77 39 54 76 } //1 #KamS6TGNCfVR03K{GyO9Z|n4xj1$w9Tv
		$a_81_2 = {7a 5a 44 65 71 75 61 77 67 35 42 59 4e 49 7a 53 36 69 75 4d 31 51 } //1 zZDequawg5BYNIzS6iuM1Q
		$a_81_3 = {65 54 4e 79 32 34 42 25 } //1 eTNy24B%
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}
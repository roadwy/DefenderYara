
rule Trojan_Win64_Stealer_SXF_MTB{
	meta:
		description = "Trojan:Win64/Stealer.SXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 05 00 00 "
		
	strings :
		$a_03_0 = {34 9d 0f b6 c0 c1 e0 08 83 f1 14 09 c1 4c 8d 44 24 ?? 66 41 89 08 48 8d 94 24 ?? ?? ?? ?? 41 b9 02 00 00 00 48 89 f1 } //20
		$a_03_1 = {4d 89 ec 4d 29 c4 4d 0f 42 c5 48 89 d9 e8 ?? ?? ?? ?? 48 98 85 c0 4c 0f 45 e0 4d 85 e4 0f 98 c0 0f 9f c1 28 c1 48 ff c5 49 83 c6 e8 48 89 f0 80 f9 01 74 } //10
		$a_01_2 = {44 65 63 72 79 70 74 69 6e 67 20 73 61 76 65 64 20 70 61 73 73 77 6f 72 64 73 } //2 Decrypting saved passwords
		$a_80_3 = {5c 6f 75 74 70 75 74 73 68 61 64 6f 77 73 6e 69 66 66 } //\outputshadowsniff  2
		$a_01_4 = {52 65 6d 65 6d 62 65 72 50 61 73 73 77 6f 72 64 } //2 RememberPassword
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*2+(#a_80_3  & 1)*2+(#a_01_4  & 1)*2) >=36
 
}

rule Trojan_Win64_Zusy_NIT_MTB{
	meta:
		description = "Trojan:Win64/Zusy.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d ac 24 ?? ?? ff ff 48 81 ec ?? ?? ?? ?? 48 8b 05 43 12 02 00 48 33 c4 48 89 85 ?? ?? ?? ?? 4d 8b e0 48 8b f9 48 bb ?? ?? ?? ?? ?? ?? ?? ?? 48 3b d1 74 22 8a 02 2c 2f 3c 2d 77 0a 48 0f be c0 48 0f a3 c3 72 10 48 8b cf e8 d2 ?? ?? ?? 48 8b d0 48 3b c7 75 de } //2
		$a_03_1 = {b8 40 41 00 00 66 c1 e3 07 b9 80 00 00 00 66 f7 d3 66 23 d9 66 0b d8 4d 85 c0 74 5f 8d 51 ae 49 8b c8 e8 17 1f 01 00 48 8b f0 48 85 c0 74 4c 48 8d 15 ?? ?? ?? ?? 48 8b c8 e8 1c 78 00 00 85 c0 74 3c 48 8d 15 ?? ?? ?? ?? 48 8b ce e8 09 78 00 00 85 c0 74 29 48 8d 15 ?? ?? ?? ?? 48 8b ce e8 f6 77 00 00 85 c0 74 16 48 8d 15 ?? ?? ?? ?? 48 8b ce e8 e3 77 00 00 85 c0 74 03 40 8a fd 48 8b 6c 24 38 0f b7 c3 48 8b 74 24 40 66 83 c8 40 40 84 ff } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=2
 
}
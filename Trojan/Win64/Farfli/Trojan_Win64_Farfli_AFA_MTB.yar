
rule Trojan_Win64_Farfli_AFA_MTB{
	meta:
		description = "Trojan:Win64/Farfli.AFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8b 0b 41 b9 00 30 00 00 4c 8b c7 33 d2 48 89 b4 24 d0 06 00 00 c7 44 24 20 40 00 00 00 48 8b f7 ff 15 41 13 01 00 48 8b f8 48 85 c0 74 5a 48 8b 0b 4c 8b ce 4c 8b c5 48 8b d0 4c 89 64 24 20 ff 15 2a 13 01 00 } //2
		$a_01_1 = {49 ff c1 b8 ef 23 b8 8f f7 e9 03 d1 c1 fa 08 8b c2 c1 e8 1f 03 d0 b8 cd cc cc cc 69 d2 c8 01 00 00 2b ca 41 f7 e2 80 c1 36 43 30 0c 03 c1 ea 03 8d 0c 92 03 c9 44 3b d1 4d 0f 44 cf 41 ff c2 49 ff c3 44 3b d7 } //2
		$a_01_2 = {64 00 33 00 33 00 66 00 33 00 35 00 31 00 61 00 34 00 61 00 65 00 65 00 61 00 35 00 65 00 36 00 30 00 38 00 38 00 35 00 33 00 64 00 31 00 61 00 35 00 36 00 36 00 36 00 31 00 30 00 35 00 39 00 } //1 d33f351a4aeea5e608853d1a56661059
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
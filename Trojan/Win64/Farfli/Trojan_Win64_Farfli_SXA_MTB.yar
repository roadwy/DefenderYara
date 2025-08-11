
rule Trojan_Win64_Farfli_SXA_MTB{
	meta:
		description = "Trojan:Win64/Farfli.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 8b e7 4d 8b ef 45 85 db 7e 1d 4c 8b d5 41 0f b7 02 66 43 39 04 10 75 0f 4c 03 ea 44 03 e2 49 83 c2 02 4d 3b eb 7c e6 45 3b e3 74 0d 03 ca 49 83 c0 02 41 3b c9 7e c8 } //3
		$a_01_1 = {41 0f b7 00 0f b7 0a 66 89 02 66 41 89 08 49 83 e8 02 48 83 c2 02 49 ff c9 75 e5 } //2
		$a_80_2 = {64 33 33 66 33 35 31 61 34 61 65 65 61 35 65 36 30 38 38 35 33 64 31 61 35 36 36 36 31 30 35 39 } //d33f351a4aeea5e608853d1a56661059  1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_80_2  & 1)*1) >=6
 
}
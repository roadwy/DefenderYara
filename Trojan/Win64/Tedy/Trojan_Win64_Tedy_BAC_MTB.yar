
rule Trojan_Win64_Tedy_BAC_MTB{
	meta:
		description = "Trojan:Win64/Tedy.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 85 dd f1 ec 53 88 cb 6d 12 2d a9 34 92 5d d3 cd ed 41 93 39 c8 ed 68 6e 46 e9 cb 2d 36 a4 02 d0 ad c5 88 bf 3d 92 26 a5 5a 3d 92 76 e0 dd d8 ed 5b d9 a2 43 40 68 c1 d7 d9 c9 74 04 22 8f 03 b5 c9 68 ee 57 ea dc 2c ff 7d c7 ae e6 3c da 4a 15 d2 3a 1f 54 df 2d d1 11 91 61 31 93 7a ee cb } //2
		$a_01_1 = {56 90 3c ad 52 54 65 2f 60 c0 c6 1d b1 42 34 53 68 2a 8f 17 89 6e 89 07 a8 88 79 5b cd e9 d7 0d 1f ad e7 96 17 e9 9e 94 d7 43 a9 99 07 93 57 f4 10 81 f2 f8 e2 e7 08 7b 89 3e f1 b6 c2 90 ec 4f 17 31 a9 91 f9 9e d7 89 2b dc 3b 13 54 da 33 88 a2 e4 80 3c 6c 3d 8f ed ab c2 38 11 0c bc 52 f5 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
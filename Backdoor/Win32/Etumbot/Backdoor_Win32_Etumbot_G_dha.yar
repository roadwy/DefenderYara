
rule Backdoor_Win32_Etumbot_G_dha{
	meta:
		description = "Backdoor:Win32/Etumbot.G!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 e9 77 c6 45 ea 72 c6 45 eb 6f c6 45 ec 74 c6 45 ed 65 c6 45 ee 28 c6 45 ef 25 c6 45 f0 64 c6 45 f1 29 c6 45 f2 2e } //01 00 
		$a_01_1 = {c6 45 b5 45 c6 45 b6 52 c6 45 b7 52 c6 45 b8 20 } //01 00 
		$a_01_2 = {c6 45 e8 45 c6 45 e9 52 c6 45 ea 52 c6 45 eb 20 c6 45 ec 27 c6 45 ed 25 c6 45 ee 73 c6 45 ef 27 } //01 00 
		$a_01_3 = {c6 45 b6 2f c6 45 b7 25 c6 45 b8 64 c6 45 b9 2e c6 45 ba 70 c6 45 bb 68 c6 45 bc 70 c6 45 bd 3f c6 45 be 25 c6 45 bf 73 } //01 00 
		$a_01_4 = {c6 45 e4 50 c6 45 e5 72 c6 45 e6 6f c6 45 e7 78 c6 45 e8 79 c6 45 e9 53 c6 45 ea 65 c6 45 eb 72 c6 45 ec 76 c6 45 ed 65 c6 45 ee 72 } //01 00 
		$a_01_5 = {c6 85 64 cd ff ff 52 c6 85 65 cd ff ff 45 c6 85 66 cd ff ff 51 c6 85 67 cd ff ff 20 c6 85 68 cd ff ff 25 c6 85 69 cd ff ff 64 c6 85 6a cd ff ff 0d } //01 00 
		$a_01_6 = {c6 45 c4 62 c6 45 c5 36 c6 45 c6 34 c6 45 c7 5f c6 45 c8 6e c6 45 c9 74 c6 45 ca 6f c6 45 cb 70 c6 45 cc 20 c6 45 cd 65 c6 45 ce 72 c6 45 cf 72 c6 45 d0 6f c6 45 d1 72 c6 45 d2 5b c6 45 d3 25 } //01 00 
		$a_01_7 = {c6 45 d0 20 c6 45 d1 65 c6 45 d2 78 c6 45 d3 65 c6 45 d4 63 c6 45 d5 75 c6 45 d6 74 c6 45 d7 65 c6 45 d8 64 c6 45 d9 2e } //01 00 
		$a_01_8 = {c6 85 a9 c7 ff ff 58 c6 85 aa c7 ff ff 44 c6 85 ab c7 ff ff 55 c6 85 ac c7 ff ff 25 c6 85 ad c7 ff ff 64 c6 85 ae c7 ff ff 3d c6 85 af c7 ff ff 25 c6 85 b0 c7 ff ff 64 c6 85 b1 c7 ff ff 2e c6 85 b2 c7 ff ff 63 c6 85 b3 c7 ff ff 67 c6 85 b4 c7 ff ff 69 c6 85 b5 c7 ff ff 3f c6 85 b6 c7 ff ff 25 c6 85 b7 c7 ff ff 73 } //01 00 
		$a_01_9 = {66 c7 85 4c f1 ff ff 73 00 66 c7 85 4e f1 ff ff 75 00 66 c7 85 50 f1 ff ff 63 00 66 c7 85 52 f1 ff ff 63 00 66 c7 85 54 f1 ff ff 65 00 66 c7 85 56 f1 ff ff 73 00 66 c7 85 58 f1 ff ff 73 00 } //01 00 
		$a_01_10 = {c6 85 a9 f6 ff ff 75 c6 85 aa f6 ff ff 73 c6 85 ab f6 ff ff 65 c6 85 ac f6 ff ff 72 c6 85 ad f6 ff ff 2f c6 85 ae f6 ff ff 72 c6 85 af f6 ff ff 65 c6 85 b0 f6 ff ff 67 c6 85 b1 f6 ff ff 69 c6 85 b2 f6 ff ff 73 c6 85 b3 f6 ff ff 74 c6 85 b4 f6 ff ff 65 c6 85 b5 f6 ff ff 72 c6 85 b6 f6 ff ff 25 c6 85 b7 f6 ff ff 64 } //01 00 
		$a_01_11 = {c6 85 cf f6 ff ff 65 c6 85 d0 f6 ff ff 70 c6 85 d1 f6 ff ff 61 c6 85 d2 f6 ff ff 67 c6 85 d3 f6 ff ff 65 c6 85 d4 f6 ff ff 26 c6 85 d5 f6 ff ff 75 c6 85 d6 f6 ff ff 72 c6 85 d7 f6 ff ff 6c c6 85 d8 f6 ff ff 3d c6 85 d9 f6 ff ff 68 c6 85 da f6 ff ff 74 c6 85 db f6 ff ff 74 c6 85 dc f6 ff ff 70 c6 85 dd f6 ff ff 73 c6 85 de f6 ff ff 25 c6 85 df f6 ff ff 73 } //01 00 
		$a_01_12 = {68 51 0f ef ff f5 26 85 11 fe ff ff 65 68 51 2f ef ff f6 36 85 13 fe ff ff 65 68 51 4f ef ff f6 96 85 15 fe ff ff 76 68 51 6f ef ff f6 56 85 17 fe ff ff 20 68 51 8f ef ff f4 36 85 19 fe ff ff 6f 68 51 af ef ff f6 d6 85 1b fe ff ff 6d 68 51 cf ef ff f6 16 85 1d fe ff ff 6e 68 51 ef ef ff f6 } //01 00 
		$a_01_13 = {c6 85 30 ff ff ff 50 c6 85 31 ff ff ff 72 c6 85 32 ff ff ff 6f c6 85 33 ff ff ff 78 c6 85 34 ff ff ff 79 c6 85 35 ff ff ff 53 c6 85 36 ff ff ff 65 c6 85 37 ff ff ff 72 c6 85 38 ff ff ff 76 c6 85 39 ff ff ff 65 c6 85 3a ff ff ff 72 } //01 00 
		$a_01_14 = {c6 45 e4 53 c6 45 e5 68 c6 45 e6 65 c6 45 e7 6c c6 45 e8 6c c6 45 e9 20 c6 45 ea 45 c6 45 eb 78 c6 45 ec 69 c6 45 ed 74 c6 45 ee 65 c6 45 ef 64 c6 45 f0 21 } //00 00 
		$a_01_15 = {00 7e } //15 00  縀
	condition:
		any of ($a_*)
 
}
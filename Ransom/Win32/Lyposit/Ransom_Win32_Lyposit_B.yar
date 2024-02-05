
rule Ransom_Win32_Lyposit_B{
	meta:
		description = "Ransom:Win32/Lyposit.B,SIGNATURE_TYPE_PEHSTR_EXT,ffffffcc 00 ffffffc8 00 0a 00 00 64 00 "
		
	strings :
		$a_01_0 = {0f b7 0b 81 f1 ef be 00 00 0f b7 c9 89 4d d8 89 45 e4 83 7d e0 00 74 2f 0f b7 c9 8b d1 c1 ea 03 c1 e1 0d } //64 00 
		$a_01_1 = {89 75 fc 66 3b 75 08 73 27 8a 01 34 cc 88 02 46 41 89 4d e4 42 89 55 e0 eb e9 } //04 00 
		$a_01_2 = {fe ff ff 59 3c 03 74 15 3c 02 74 0d 68 a0 bb 0d 00 ff 15 } //04 00 
		$a_03_3 = {6a 7c 8b cf e8 90 01 02 00 00 83 c4 0c 88 45 e7 3c 03 0f 82 b0 01 00 00 8a 5d 08 89 7d dc 84 db 74 15 8b 7d dc 57 ff 15 90 00 } //02 00 
		$a_01_4 = {fd 3f 5a 05 bc 3f fe bd 45 83 ac e6 1e 9d f3 bc 57 91 f3 a4 08 99 f3 af 5f 9a fd ac 1f 90 f9 a4 } //02 00 
		$a_01_5 = {51 89 18 bc 45 81 15 ad 1e 9c 0b ab 1f 92 1d e3 4c 9b 0d b8 40 c9 56 e3 59 84 11 aa 08 96 16 a4 } //02 00 
		$a_01_6 = {ff 3f 5f 0b ed 3f c0 a8 55 87 e4 a6 41 96 cf 8a 5a 90 e1 a8 40 9c f5 b3 70 fb 25 } //02 00 
		$a_01_7 = {fe 5f ae 06 ec 5f 31 a5 54 e7 15 ab 40 f6 3e 87 5b f0 10 a5 41 fc 04 be 36 a7 7d } //02 00 
		$a_01_8 = {40 77 0f 2d 40 e8 ac aa f8 cc a2 be e9 e7 8e a5 ef c9 ac bf e3 dd b7 90 db d2 ad a8 e3 cc b0 90 } //02 00 
		$a_01_9 = {5a 70 20 a9 40 7c 34 b2 6f 44 3b a8 57 7c 25 b5 6f 50 27 b4 41 76 3c b2 65 76 20 b5 5a 7c 3c 9a } //00 00 
		$a_00_10 = {80 10 00 00 } //95 5e 
	condition:
		any of ($a_*)
 
}
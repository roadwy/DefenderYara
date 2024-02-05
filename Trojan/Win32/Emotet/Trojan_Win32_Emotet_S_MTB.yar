
rule Trojan_Win32_Emotet_S_MTB{
	meta:
		description = "Trojan:Win32/Emotet.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 e0 8a 0c 05 90 01 04 8b 55 ec 8b 75 dc 8a 2c 32 28 cd 8b 7d e8 88 2c 37 83 c6 01 8b 5d f0 39 de 89 75 e4 73 90 00 } //01 00 
		$a_02_1 = {8b 45 d8 8a 0c 05 90 01 04 8b 55 e8 8b 75 dc 8a 2c 32 28 cd 8b 7d e4 88 2c 37 83 c6 01 8b 5d ec 39 de 89 75 e0 72 90 00 } //01 00 
		$a_02_2 = {8b 45 dc 8b 4d d8 ba 90 01 04 89 45 d4 31 f6 89 55 d0 89 f2 8b 75 d0 f7 f6 8b 7d d4 83 e7 03 83 f9 02 0f 47 fa 8a 1c 3d 90 01 04 8b 55 ec 8b 7d d4 8a 3c 3a 28 df 01 f9 8b 55 e8 88 3c 3a 83 c7 90 01 01 8b 55 f0 39 d7 89 4d d8 89 7d dc 72 b0 90 00 } //01 00 
		$a_02_3 = {8b 7d cc 01 cf 89 4d c4 8b 4d e8 89 55 c0 8b 55 c4 8a 0c 11 8b 55 cc 39 f2 8b 75 c0 0f 47 de 2a 0c 1d 90 01 04 8b 75 e4 8b 5d c4 88 0c 1e 83 c3 33 8b 4d ec 39 cb 89 5d d4 89 7d d0 72 90 00 } //01 00 
		$a_02_4 = {8b 45 d4 8b 4d d0 ba 90 01 04 89 45 cc 89 c8 31 f6 89 55 c8 89 f2 8b 75 c8 f7 f6 89 cf 83 e7 03 8b 5d e8 8a 1c 0b 8b 75 cc 83 fe 02 0f 47 fa 01 ce 2a 1c 3d 97 41 40 00 8b 55 e4 88 1c 0a 83 c1 33 8b 7d ec 39 f9 89 75 d4 89 4d d0 72 b1 90 00 } //01 00 
		$a_02_5 = {8b 45 ec 8b 4d b8 8a 14 01 8b 45 ec 03 45 dc 8b 75 e8 8a 75 c3 f6 c6 01 0f 44 75 c4 8a 34 35 90 01 04 8b 75 ec 28 f2 8b 7d b4 88 14 37 8b 75 ec 83 c6 33 89 45 e4 89 45 e0 89 75 cc 8b 45 bc 39 c6 0f 82 90 01 01 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
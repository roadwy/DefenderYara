
rule TrojanDropper_Win32_SpamThru_gen_E{
	meta:
		description = "TrojanDropper:Win32/SpamThru.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {99 59 8d 9e ff 00 00 00 f7 f9 8d 0c bf 0f be 82 90 01 04 03 c1 b9 f1 ff 00 00 8b f8 99 f7 f9 8b 4d 08 8d 8c 0e 90 01 04 8b c2 33 d2 89 45 f8 25 ff 00 00 00 f7 f1 0f be 8e 90 01 04 80 be 90 01 04 00 8d 82 90 01 04 8a 92 90 01 04 88 96 90 01 04 88 08 75 26 33 c0 33 d2 8a 45 f9 f7 f3 80 ba 90 01 04 00 74 08 8d 42 01 99 f7 fb eb ef 88 93 90 01 04 88 9a 90 01 04 ff 45 fc 4e 81 fe 00 ff ff ff 0f 8f 69 ff ff ff 5f 5e 33 c0 5b 0f b6 88 90 01 04 88 81 90 01 04 40 90 00 } //01 00 
		$a_00_1 = {8b 44 8e e4 89 44 8f e4 8b 44 8e e8 89 44 8f e8 8b 44 8e ec 89 44 8f ec 8b 44 8e f0 89 44 8f f0 8b 44 8e f4 89 44 8f f4 8b 44 8e f8 89 44 8f f8 8b 44 8e fc 89 44 8f fc 8d 04 8d 00 00 00 00 03 f0 03 f8 ff 24 95 } //01 00 
		$a_02_2 = {ec cc 00 00 00 8d 45 f0 50 ff 15 90 01 04 8d 45 e0 50 ff 15 90 01 04 66 8b 45 ea 66 3b 05 90 01 04 75 3b 66 8b 45 e8 66 3b 05 90 01 04 75 2e 66 8b 45 e6 66 3b 05 90 01 04 75 21 66 8b 45 e2 66 3b 05 90 01 04 75 14 66 8b 45 e0 66 3b 05 90 01 04 75 07 a1 90 01 04 eb 45 8d 85 34 ff ff ff 50 ff 15 90 01 04 83 f8 ff 74 1b 83 f8 02 75 12 66 83 7d ce 00 74 0b 83 7d dc 00 74 05 6a 01 58 eb 07 33 c0 eb 03 83 c8 ff 56 57 8d 75 e0 bf 90 01 04 a5 a5 a5 a5 5f a3 90 01 04 5e 50 0f b7 45 fc 50 0f b7 45 fa 50 0f b7 45 f8 50 0f b7 45 f6 50 0f b7 45 f2 50 0f b7 45 f0 50 e8 ee 1d 00 00 8b 4d 08 83 c4 1c 85 c9 74 02 89 01 c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
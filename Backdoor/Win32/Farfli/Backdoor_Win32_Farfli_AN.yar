
rule Backdoor_Win32_Farfli_AN{
	meta:
		description = "Backdoor:Win32/Farfli.AN,SIGNATURE_TYPE_PEHSTR_EXT,ffffffbe 00 ffffffaa 00 06 00 00 64 00 "
		
	strings :
		$a_01_0 = {c6 45 f4 5c c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c } //32 00 
		$a_01_1 = {b9 00 5c 26 05 33 d2 8b f9 8b f0 f7 f7 33 d2 89 45 08 8b c6 f7 f1 b9 80 ee 36 00 } //14 00 
		$a_01_2 = {a1 b8 bf aa ca bc a1 b9 b2 cb b5 a5 5c b3 cc d0 f2 5c 53 74 61 72 74 75 70 5c 68 61 6f 35 36 37 2e 65 78 65 } //14 00 
		$a_01_3 = {c6 45 f5 6f c6 45 f6 75 c6 45 f7 72 c6 45 f8 6c c6 45 f9 6f } //14 00 
		$a_01_4 = {c6 45 c4 4b c6 45 c5 65 c6 45 c6 79 c6 45 90 41 c6 45 91 44 c6 45 92 56 } //14 00 
		$a_01_5 = {0f b7 d0 0f af 55 0c 8b 4d 10 83 c2 1f c1 fa 03 83 e2 fc c7 06 28 00 00 00 0f af d1 83 f8 10 } //00 00 
		$a_00_6 = {5d 04 00 00 77 fb 02 80 5c 22 00 00 78 fb 02 80 00 00 01 00 08 00 0c 00 ac 21 46 6f 64 69 72 77 65 6e 2e 41 00 00 01 40 05 82 70 00 04 00 80 10 00 00 9a 72 2c 1c d6 ae 73 0a 39 a0 dc 7d 00 40 00 80 5d 04 00 00 78 fb 02 80 5c 27 00 00 79 fb 02 80 00 00 01 00 22 00 11 00 cc 21 56 42 49 6e 6a 65 63 74 2e 67 65 6e 21 4a 56 00 00 01 40 05 82 31 00 04 00 78 85 00 } //00 01 
	condition:
		any of ($a_*)
 
}
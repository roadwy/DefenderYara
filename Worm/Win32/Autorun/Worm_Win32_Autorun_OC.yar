
rule Worm_Win32_Autorun_OC{
	meta:
		description = "Worm:Win32/Autorun.OC,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 e8 c6 07 fb ff 83 e8 02 0f 85 f6 02 00 00 8b 45 f4 e8 51 f8 ff ff 84 c0 0f 84 e6 02 00 00 33 c0 55 68 ef 5b 45 00 64 ff 30 64 89 20 8d 45 e8 b9 84 5c 45 00 8b 55 f4 e8 23 ea fa ff 8b 45 e8 e8 83 2b fb ff 84 c0 0f 85 92 00 00 00 33 c0 55 68 d1 59 45 00 64 ff 30 64 89 20 b3 01 80 fb 01 f5 1b c0 50 8d 45 e4 b9 84 5c 45 00 8b 55 f4 e8 ec e9 fa ff 8b 45 e4 e8 98 eb fa ff 50 8d 55 e0 a1 a0 70 45 00 8b 00 e8 ac cf ff ff 8b 45 e0 e8 80 eb fa ff 50 e8 72 06 fb ff 8d 45 dc b9 84 5c 45 00 } //01 00 
		$a_01_1 = {64 6c 6c 2e 65 78 65 00 ff ff ff ff 2e 00 00 00 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 72 75 6e } //01 00 
		$a_01_2 = {64 72 69 76 65 72 2e 65 78 65 00 00 ff ff ff ff 0b 00 00 00 61 75 74 6f 72 75 6e 2e 69 6e 66 } //00 00 
	condition:
		any of ($a_*)
 
}
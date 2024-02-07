
rule PWS_Win32_Wowsteal_gen_B{
	meta:
		description = "PWS:Win32/Wowsteal.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 05 00 "
		
	strings :
		$a_00_0 = {32 e4 3c 41 72 3c 3c 5a 76 3a 3c 61 72 34 3c 7a 76 32 3c 80 72 2c 3c 83 72 2a 74 26 3c 85 72 24 74 20 3c 87 76 1e 3c 8e 72 18 3c 90 76 16 3c 94 74 12 3c 99 74 0e 3c 9a 74 0a 3c a4 74 06 3c a5 74 02 f6 d4 c3 } //05 00 
		$a_00_1 = {3c 41 72 37 3c 5a 76 31 3c 8e 74 1b 3c 99 74 1a 3c 9a 74 19 3c 90 74 18 3c a5 74 17 3c 8f 74 16 3c 80 75 17 b0 87 c3 b0 84 c3 b0 94 c3 b0 81 c3 b0 82 c3 b0 a4 c3 b0 86 c3 34 20 c3 } //05 00 
		$a_02_2 = {56 49 75 fc 8d 9d 74 ff ff ff 89 33 53 df 05 90 01 04 df 05 90 01 04 e8 90 01 04 e8 90 01 04 50 ff 15 90 01 04 e8 90 01 04 50 ff 15 90 01 04 8b b5 74 ff ff ff e8 90 01 04 85 c0 0f 84 e0 00 00 00 6a 00 6a 00 8d 9d 6c ff ff ff 53 ba 90 01 04 e8 90 01 04 8b dc 83 c3 08 e8 90 01 04 ba 90 01 04 e8 90 01 04 8b dc 83 c3 08 90 00 } //01 00 
		$a_01_3 = {40 56 69 73 69 6f 6e 40 } //01 00  @Vision@
		$a_01_4 = {57 6f 57 2e 65 78 65 } //01 00  WoW.exe
		$a_01_5 = {47 61 6d 65 50 61 73 73 } //01 00  GamePass
		$a_01_6 = {4c 6f 76 45 66 33 } //00 00  LovEf3
	condition:
		any of ($a_*)
 
}
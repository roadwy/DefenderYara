
rule Worm_Win32_Yalove_A{
	meta:
		description = "Worm:Win32/Yalove.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8d 45 fc 8b cb ba 90 01 04 e8 90 01 02 ff ff 68 02 00 00 80 8d 45 f8 8b 55 fc e8 90 01 02 ff ff 8b 45 f8 b9 90 01 04 ba 90 01 04 e8 90 01 02 ff ff 33 c0 5a 59 59 64 89 10 68 90 01 04 8d 45 f8 90 00 } //0a 00 
		$a_02_1 = {68 02 00 00 80 b9 90 01 04 ba 90 01 04 b8 90 01 04 e8 90 01 02 ff ff 68 02 00 00 80 b9 90 01 04 ba 90 01 04 b8 90 01 04 e8 90 01 02 ff ff 8d 95 90 01 02 ff ff a1 90 01 04 e8 90 01 02 ff ff 8b 95 90 01 02 ff ff 8d 45 f4 b9 90 01 04 e8 90 01 02 ff ff 8b 55 f4 a1 90 01 04 e8 90 01 02 ff ff 8b 45 f4 e8 90 01 02 ff ff 6a 64 90 00 } //01 00 
		$a_00_2 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_00_3 = {41 00 55 00 54 00 4f 00 52 00 55 00 4e 00 2e 00 49 00 4e 00 46 00 } //00 00  AUTORUN.INF
	condition:
		any of ($a_*)
 
}
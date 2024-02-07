
rule Backdoor_Linux_Flashback_C{
	meta:
		description = "Backdoor:Linux/Flashback.C,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 } //01 00  IOPlatformUUID
		$a_01_1 = {b8 68 58 4d 56 bb 12 f7 6c 3c b9 0a 00 00 00 ba 58 56 00 00 } //01 00 
		$a_01_2 = {c1 e8 02 ba 15 02 4d 21 f7 e2 c1 ea 04 } //01 00 
		$a_01_3 = {01 ce 89 da 89 d8 c1 fa 1f f7 ff 8b 85 38 f9 ff ff 0f b6 04 10 01 c6 89 f0 0f b6 d0 } //01 00 
		$a_03_4 = {83 ec 2c c7 44 24 04 90 01 02 00 00 8b 45 0c 8b 00 89 04 24 e8 90 01 02 00 00 89 c3 85 c0 75 24 90 00 } //02 00 
		$a_03_5 = {44 89 ea 32 14 03 0f be f2 4c 89 e7 e8 90 01 02 00 00 48 ff c3 49 8b 06 48 3b 58 e8 72 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
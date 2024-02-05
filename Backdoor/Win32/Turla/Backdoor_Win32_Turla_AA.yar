
rule Backdoor_Win32_Turla_AA{
	meta:
		description = "Backdoor:Win32/Turla.AA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {48 83 ec 48 4c 8d 0d c1 ef ff ff 31 d2 31 c9 4c 8d 05 b6 f3 ff ff 48 8d 44 24 3c c7 44 24 3c 00 00 00 00 48 89 44 24 28 c7 44 24 20 00 00 00 00 ff 15 2e 50 00 00 } //02 00 
		$a_00_1 = {48 83 ec 38 ff ca 75 1d 48 89 4c 24 28 e8 9a ff ff ff 48 8b 4c 24 28 84 c0 74 0a e8 1c ff ff ff e8 4b ff ff ff b8 01 00 00 00 48 83 c4 38 c3 } //02 00 
		$a_00_2 = {55 89 e5 83 ec 18 83 7d 0c 01 75 19 e8 8f ff ff ff 84 c0 74 10 8b 45 08 89 04 24 e8 f8 fe ff ff e8 33 ff ff ff b8 01 00 00 00 c9 c2 0c 00 } //02 00 
		$a_00_3 = {89 e5 83 ec 38 8d 45 f4 c7 45 f4 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 20 a0 6a c7 44 24 08 00 24 a0 6a 89 44 24 14 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff 15 74 60 a0 6a } //01 00 
		$a_02_4 = {01 00 64 6c 90 01 02 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 90 02 05 00 48 6f 6f 6b 50 72 6f 63 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
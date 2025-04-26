
rule Worm_Win32_Kulsibot_gen_A{
	meta:
		description = "Worm:Win32/Kulsibot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0f 00 09 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 6b 20 65 63 68 6f 20 6f 70 65 6e 20 25 73 20 25 64 20 3e 20 6f 26 65 63 68 6f 20 75 73 65 72 20 61 20 62 20 3e 3e 20 6f 26 65 63 68 6f 20 62 69 6e 61 72 79 20 3e 3e 20 6f 26 65 63 68 6f 20 67 65 74 } //5 cmd /k echo open %s %d > o&echo user a b >> o&echo binary >> o&echo get
		$a_00_1 = {50 43 20 4e 45 54 57 4f 52 4b 20 50 52 4f 47 52 41 4d 20 31 2e 30 } //1 PC NETWORK PROGRAM 1.0
		$a_01_2 = {4c 41 4e 4d 41 4e 31 2e 30 } //1 LANMAN1.0
		$a_00_3 = {4c 41 4e 4d 41 4e 32 2e 31 } //1 LANMAN2.1
		$a_01_4 = {57 69 6e 64 6f 77 73 20 66 6f 72 20 57 6f 72 6b 67 72 6f 75 70 73 20 33 2e 31 61 } //1 Windows for Workgroups 3.1a
		$a_01_5 = {43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 } //1 CACACACACACACACACACACACACACACA
		$a_03_6 = {68 8b 00 00 00 56 e8 ?? ?? ?? ?? 83 c4 ?? 83 f8 01 75 e1 68 8b 00 00 00 56 ff d7 50 e8 ?? ?? ?? ?? eb d1 } //5
		$a_03_7 = {68 bd 01 00 00 56 e8 ?? ?? ?? ?? 83 c4 ?? 83 f8 01 75 e1 68 bd 01 00 00 56 ff d7 50 e8 ?? ?? ?? ?? eb d1 } //5
		$a_03_8 = {03 d9 81 e3 ff 00 00 00 8a 4c 1c ?? 8a 1c 28 32 d9 88 1c 28 40 3b c2 72 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*5+(#a_03_7  & 1)*5+(#a_03_8  & 1)*5) >=15
 
}
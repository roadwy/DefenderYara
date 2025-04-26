
rule VirTool_Win32_CeeInject_gen_L{
	meta:
		description = "VirTool:Win32/CeeInject.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,51 00 50 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6c 75 6c 68 65 6c 6c 6f 77 6f 72 6c 64 63 70 70 66 74 77 } //1 lulhelloworldcppftw
		$a_01_1 = {6c 61 6c 61 6c 61 2e 2e 2e 2e 24 24 24 24 24 24 } //1 lalala....$$$$$$
		$a_01_2 = {6d 76 75 61 32 6e 34 33 67 61 31 33 31 33 31 33 31 } //1 mvua2n43ga1313131
		$a_01_3 = {6d 75 76 61 6e 32 68 34 67 6e 6e 6a 32 76 6e 76 6e 6a 61 76 32 6e 6a 61 34 76 6e 6a 61 34 76 } //1 muvan2h4gnnj2vnvnjav2nja4vnja4v
		$a_01_4 = {6c 61 75 6c 67 75 6c 68 75 61 68 31 32 33 31 } //1 laulgulhuah1231
		$a_01_5 = {6c 75 6c 7a 62 61 72 } //1 lulzbar
		$a_01_6 = {6e 6a 76 6a 6e 61 72 6a 67 61 68 6a 6e 72 76 61 6a 72 76 6e 32 6a 6f 6e 65 } //1 njvjnarjgahjnrvajrvn2jone
		$a_01_7 = {64 62 67 68 65 6c 70 2e 64 6c 6c 00 53 62 69 65 44 6c 6c 2e 64 6c 6c } //20
		$a_01_8 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed 89 5d e4 5b 83 4d fc ff eb 14 } //20
		$a_01_9 = {b8 01 00 00 00 0f 3f 07 0b c7 45 fc ff ff ff ff 83 4d fc ff eb 14 } //20
		$a_01_10 = {8b 95 f0 fe ff ff 03 d0 03 ca 8b c1 99 b9 00 01 00 00 f7 f9 89 95 f0 fe ff ff } //20
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*20+(#a_01_8  & 1)*20+(#a_01_9  & 1)*20+(#a_01_10  & 1)*20) >=80
 
}

rule TrojanDropper_Win32_Cutwail_R{
	meta:
		description = "TrojanDropper:Win32/Cutwail.R,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 0d 00 00 "
		
	strings :
		$a_02_0 = {75 f9 83 05 ?? ?? ?? ?? 04 ff 15 ?? ?? 40 00 83 c4 1c ff 15 ?? ?? 40 00 83 f0 06 f7 d0 [0-02] 8d 75 f4 } //4
		$a_02_1 = {8b 4d 08 8b 55 0c 80 01 ?? 41 4a 75 f9 83 05 ?? ?? ?? ?? 04 } //4
		$a_02_2 = {8d b5 2c fd ff ff c7 06 02 00 01 00 56 ff 75 fc ff 15 ?? ?? 40 00 8b 45 0c 89 86 b0 00 00 00 56 ff 75 fc } //3
		$a_01_3 = {b9 a0 00 00 00 8d 1d 64 20 40 00 03 d9 } //3
		$a_01_4 = {80 f9 00 74 0e 8a 13 32 d1 88 16 48 74 0c 43 46 47 eb eb } //3
		$a_03_5 = {c7 44 24 fc 00 50 c3 00 90 09 02 00 ff } //3
		$a_03_6 = {c7 44 24 fc 00 00 00 00 81 4c 24 fc 00 50 c3 00 90 09 02 00 ff } //3
		$a_03_7 = {b8 04 50 c3 00 ba 04 00 00 00 90 09 02 00 ff } //3
		$a_02_8 = {83 c0 02 ff d0 90 09 06 00 8d 05 ?? ?? ?? 00 } //1
		$a_02_9 = {83 e8 03 ff d0 90 09 06 00 8d 05 ?? ?? ?? 00 } //1
		$a_02_10 = {41 ff d1 c3 90 09 06 00 8d 0d ?? ?? ?? 00 } //1
		$a_01_11 = {ff 04 24 59 e2 ff e1 } //1
		$a_01_12 = {eb 03 e8 61 6c 8d 15 } //1
	condition:
		((#a_02_0  & 1)*4+(#a_02_1  & 1)*4+(#a_02_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_03_5  & 1)*3+(#a_03_6  & 1)*3+(#a_03_7  & 1)*3+(#a_02_8  & 1)*1+(#a_02_9  & 1)*1+(#a_02_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=4
 
}
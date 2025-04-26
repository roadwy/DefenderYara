
rule TrojanDropper_Win32_Hupigon_UC{
	meta:
		description = "TrojanDropper:Win32/Hupigon.UC,SIGNATURE_TYPE_PEHSTR_EXT,70 00 70 00 05 00 00 "
		
	strings :
		$a_00_0 = {00 43 3a 5c 77 77 77 5c 68 75 69 67 65 7a 69 2e 63 4f 6d 00 00 4f 70 65 4e 00 } //100
		$a_00_1 = {53 56 57 8b fa 8b f0 33 db 8a 1e eb 01 4b 83 fb 01 7e 0b 8a 04 1e 2c 3a 74 04 2c 22 75 ef 57 8b c6 ba 01 00 00 00 8b cb e8 ab e0 ff ff 8a 07 84 c0 76 0d 25 ff 00 00 00 80 3c 07 00 75 02 fe 0f 5f 5e 5b c3 } //10
		$a_00_2 = {53 56 57 8b fa 8b f0 33 db 8a 1e eb 01 4b 83 fb 01 7e 0f 8a 04 1e 2c 2e 74 08 2c 0c 74 04 2c 22 75 eb 83 fb 01 7e 17 80 3c 1e 2e 75 11 57 8b c6 b9 ff 00 00 00 8b d3 e8 10 e0 ff ff eb 03 c6 07 00 8a 07 84 c0 76 0d 25 ff 00 00 00 80 3c 07 00 75 02 fe 0f 5f 5e 5b c3 } //10
		$a_02_3 = {00 43 3a 5c 77 77 77 5c 68 75 69 67 65 7a 69 38 ?? ?? ?? 2e 63 } //1
		$a_02_4 = {00 43 3a 5c 77 77 77 5c 68 75 69 67 65 7a 69 35 ?? ?? ?? 2e 63 } //1
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=112
 
}
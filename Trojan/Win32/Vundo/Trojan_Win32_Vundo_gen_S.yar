
rule Trojan_Win32_Vundo_gen_S{
	meta:
		description = "Trojan:Win32/Vundo.gen!S,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff d7 85 c0 0f 84 90 01 01 00 00 00 ff b5 90 01 02 ff ff 8d 45 90 01 01 50 68 90 01 03 10 e8 90 16 90 01 1b 89 45 fc 76 12 33 d2 8b c1 f7 75 fc 8a 04 3a 30 04 31 90 00 } //1
		$a_03_1 = {ff 75 08 6a 48 50 e8 90 16 90 01 2d 8b 45 14 8b 7c 85 f8 6a 22 83 ee 22 56 57 e8 90 01 01 ff ff ff 83 c4 0c 4e 8a 06 4e 8a 0e 32 c1 90 00 } //1
		$a_03_2 = {eb 20 53 ff b5 90 01 02 ff ff ff 15 90 01 03 10 6a 0a 8d 4d d4 51 50 e8 90 01 02 00 00 83 c4 0c 90 00 } //1
		$a_01_3 = {74 27 83 7d fc 10 75 21 8b 45 10 3b c3 8b 4d f8 74 02 89 08 38 5d 14 74 0e 8b 45 0c 6a 04 5a 31 08 83 c0 04 4a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}
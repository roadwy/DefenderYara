
rule Virus_Win32_Ursnif_F{
	meta:
		description = "Virus:Win32/Ursnif.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 06 0f b6 c0 46 83 e8 33 74 20 83 e8 33 74 34 83 e8 4a 74 11 83 e8 08 75 12 8b 06 89 01 83 c1 04 83 c6 04 eb 06 8a 06 88 01 41 46 3b f3 75 d0 } //1
		$a_01_1 = {8b fa 8b df c1 eb 02 83 e7 03 8b f1 85 db 74 1f 8a 44 24 14 8b 16 02 c3 0f b6 c8 8b 44 24 10 d3 ca 33 d0 2b d3 89 16 83 c6 04 4b 75 e3 } //1
		$a_01_2 = {6a 48 8d b7 00 04 00 00 8b d6 8d 4d b0 e8 a8 03 00 00 51 ff 76 4c 8d 4d b0 ff 76 48 6a 48 5a e8 7e 00 00 00 8b 4d b0 8b 55 b4 8d 45 f8 50 8d 45 fc 81 c1 00 04 00 00 50 03 cf e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
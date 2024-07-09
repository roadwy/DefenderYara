
rule Virus_Win32_Madang_gen_A{
	meta:
		description = "Virus:Win32/Madang.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 8d 5f 2c 53 e8 ?? ff ff ff 3d 2e 65 78 65 74 0b 3d 2e 73 63 72 74 04 c9 c2 04 00 6a 64 ff 56 } //1
		$a_03_1 = {66 81 3f 50 45 0f 85 ?? 00 00 00 81 bf 9b 01 00 00 79 6c 50 7a 0f 84 ?? 00 00 00 } //1
		$a_03_2 = {58 66 3d 60 e8 0f 84 ?? 00 00 00 81 4b 24 00 00 00 e0 6a 02 6a 00 ff 75 08 ff 56 } //1
		$a_01_3 = {81 ec 00 10 00 00 c7 04 24 2a 2e 2a 00 8b c4 54 50 ff 56 } //1
		$a_00_4 = {73 65 74 75 70 78 } //1 setupx
		$a_00_5 = {76 67 75 61 72 64 65 72 } //1 vguarder
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}
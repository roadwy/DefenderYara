
rule TrojanDownloader_Win32_Obitel_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Obitel.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_03_0 = {89 75 f8 33 c0 8a 4c 05 ?? 80 c1 07 00 4c 35 ?? 40 83 f8 15 72 02 33 c0 46 83 fe 0b } //2
		$a_01_1 = {7f 03 80 c1 20 8b da 0f a4 fa 0f 33 ed 0f be c1 0b ea c1 eb 11 c1 e7 0f 99 } //1
		$a_01_2 = {eb 11 8b 5d fc 0f be d2 c1 c3 0d 33 da 47 8a 17 89 5d fc 84 d2 75 eb } //1
		$a_03_3 = {3d 38 23 f1 d0 75 ?? 81 fa f9 39 9d a1 75 } //2
		$a_01_4 = {c7 04 24 73 8d c7 26 } //1
		$a_03_5 = {8a 00 3c 3b 74 2d 3a c3 74 29 3c 0d 74 25 3c 0a 74 21 8b 4f 90 09 0c 00 0f 83 } //3
		$a_03_6 = {8b 08 50 ff 51 1c 85 c0 7c 4d eb 17 8d 86 ?? ?? 00 00 8b 08 83 f9 01 74 05 83 f9 02 75 1e } //3
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1+(#a_03_5  & 1)*3+(#a_03_6  & 1)*3) >=3
 
}
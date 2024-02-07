
rule Trojan_Win32_Zloader_C_ibt{
	meta:
		description = "Trojan:Win32/Zloader.C!ibt,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 45 08 89 c1 81 f1 f2 00 00 00 89 ca 0f af d0 31 d1 0f af ca 29 d1 81 f1 ae 02 00 00 8d 91 44 ff ff ff 89 d6 0f af f1 09 f2 0f be d2 01 f2 89 d6 29 ce 21 ce 35 77 d8 dd 9d 01 f1 0f af ca 0f af ce 0f af c9 69 c9 d0 01 00 00 } //01 00 
		$a_03_1 = {8b 5d 0c b9 c1 de 31 35 89 d8 89 de f7 e1 c1 ea 07 69 c2 68 02 00 00 29 c6 8b 0c b5 90 01 04 85 c9 74 2f 31 c0 90 90 90 90 90 02 10 39 d9 0f 84 96 00 00 00 81 fe 66 02 00 00 8d 76 01 0f 4f f0 8b 0c b5 90 01 04 85 c9 75 e1 90 00 } //01 00 
		$a_03_2 = {53 57 56 81 ec 90 01 02 00 00 e8 90 01 04 e8 90 01 04 e8 90 01 04 e8 90 01 04 be ff ff ff ff e8 90 01 04 84 c0 0f 84 90 01 02 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zloader_C_ibt_2{
	meta:
		description = "Trojan:Win32/Zloader.C!ibt,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 61 74 68 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 57 61 6c 6b 6b 6e 65 77 00 } //01 00  慰桴搮汬䐀汬敒楧瑳牥敓癲牥圀污歫敮w
		$a_01_1 = {53 61 6d 65 41 66 72 61 69 64 5c 61 6e 69 6d 61 6c 53 74 6f 6e 65 5c 6f 75 72 57 69 66 65 5c 4c 69 71 75 69 64 4a 75 73 74 5c 70 61 74 68 2e 70 64 62 } //01 00  SameAfraid\animalStone\ourWife\LiquidJust\path.pdb
		$a_01_2 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_01_3 = {49 6e 74 65 72 6e 65 74 57 72 69 74 65 46 69 6c 65 } //01 00  InternetWriteFile
		$a_01_4 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 45 78 57 } //00 00  HttpSendRequestExW
	condition:
		any of ($a_*)
 
}
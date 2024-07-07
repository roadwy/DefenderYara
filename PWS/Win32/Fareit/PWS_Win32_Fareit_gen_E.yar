
rule PWS_Win32_Fareit_gen_E{
	meta:
		description = "PWS:Win32/Fareit.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 46 61 72 32 5c 53 61 76 65 64 44 69 61 6c 6f 67 48 69 73 74 6f 72 79 5c 46 54 50 48 6f 73 74 } //1 Software\Far2\SavedDialogHistory\FTPHost
		$a_00_1 = {5c 56 61 6e 44 79 6b 65 5c 43 6f 6e 66 69 67 5c 53 65 73 73 69 6f 6e 73 } //1 \VanDyke\Config\Sessions
		$a_01_2 = {00 6f 69 64 2e 62 61 74 00 } //2
		$a_01_3 = {00 61 62 63 64 2e 62 61 74 00 } //2
		$a_01_4 = {80 3f 09 74 19 80 3f 0d 74 14 80 3f 0a 74 0f 80 3f 5b 74 0a 80 3f 5d 74 05 80 3f 60 75 03 c6 07 20 47 80 3f 00 75 d9 } //10
		$a_03_5 = {eb 2d 8b 17 8b 45 08 25 ff 7f ff ff 39 42 04 75 1b 6a 00 8d 42 08 50 68 90 01 04 ff 32 e8 90 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*10+(#a_03_5  & 1)*10) >=2
 
}
rule PWS_Win32_Fareit_gen_E_2{
	meta:
		description = "PWS:Win32/Fareit.gen!E!!Fareit.gen!E,SIGNATURE_TYPE_ARHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 46 61 72 32 5c 53 61 76 65 64 44 69 61 6c 6f 67 48 69 73 74 6f 72 79 5c 46 54 50 48 6f 73 74 } //1 Software\Far2\SavedDialogHistory\FTPHost
		$a_00_1 = {5c 56 61 6e 44 79 6b 65 5c 43 6f 6e 66 69 67 5c 53 65 73 73 69 6f 6e 73 } //1 \VanDyke\Config\Sessions
		$a_01_2 = {00 6f 69 64 2e 62 61 74 00 } //2
		$a_01_3 = {00 61 62 63 64 2e 62 61 74 00 } //2
		$a_01_4 = {80 3f 09 74 19 80 3f 0d 74 14 80 3f 0a 74 0f 80 3f 5b 74 0a 80 3f 5d 74 05 80 3f 60 75 03 c6 07 20 47 80 3f 00 75 d9 } //10
		$a_03_5 = {eb 2d 8b 17 8b 45 08 25 ff 7f ff ff 39 42 04 75 1b 6a 00 8d 42 08 50 68 90 01 04 ff 32 e8 90 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*10+(#a_03_5  & 1)*10) >=12
 
}
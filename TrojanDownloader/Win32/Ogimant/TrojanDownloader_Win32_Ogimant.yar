
rule TrojanDownloader_Win32_Ogimant{
	meta:
		description = "TrojanDownloader:Win32/Ogimant,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0c 00 00 "
		
	strings :
		$a_01_0 = {6d 69 6e 69 6d 61 6c 5f 77 61 72 65 } //2 minimal_ware
		$a_01_1 = {38 2e 38 2e 38 2e 38 } //2 8.8.8.8
		$a_01_2 = {4d 69 6e 69 4d 61 6c 77 61 72 65 } //2 MiniMalware
		$a_01_3 = {62 6c 61 20 62 6c 61 20 62 6c 61 } //2 bla bla bla
		$a_01_4 = {63 72 65 61 74 65 64 5f 61 6e 64 5f 6d 6f 64 69 66 69 65 64 2e 74 78 74 } //2 created_and_modified.txt
		$a_01_5 = {63 72 65 61 74 65 64 5f 61 6e 64 5f 64 65 6c 65 74 65 64 2e 74 78 74 } //2 created_and_deleted.txt
		$a_01_6 = {63 72 65 61 74 65 64 2e 74 78 74 } //2 created.txt
		$a_01_7 = {63 72 65 61 74 65 64 5f 61 6e 64 5f 72 65 6e 61 6d 65 2e 74 78 74 } //2 created_and_rename.txt
		$a_01_8 = {61 66 74 65 72 5f 72 65 6e 61 6d 65 5f 66 69 6c 65 2e 74 78 74 } //2 after_rename_file.txt
		$a_01_9 = {63 72 65 61 74 65 64 5f 61 6e 64 5f 72 65 6e 61 6d 65 32 2e 74 78 74 } //2 created_and_rename2.txt
		$a_01_10 = {63 72 65 61 74 65 64 5f 61 6e 64 5f 6d 6f 76 65 64 2e 74 78 74 } //2 created_and_moved.txt
		$a_01_11 = {61 66 74 65 72 5f 6d 6f 76 65 5f 66 69 6c 65 2e 74 78 74 } //2 after_move_file.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2) >=24
 
}
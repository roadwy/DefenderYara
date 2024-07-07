
rule Ransom_Win64_Knight_ZA_MTB{
	meta:
		description = "Ransom:Win64/Knight.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 ff c3 48 b8 90 02 0a 48 f7 e1 48 c1 ea 90 01 01 48 6b c2 90 01 01 48 2b c8 0f be 44 0c 90 01 01 66 41 89 06 4d 8d 76 90 01 01 3b 9c 24 90 01 04 72 90 00 } //1
		$a_03_1 = {42 8a 4c 04 90 01 01 41 8d 40 90 01 01 41 30 09 45 33 c0 49 ff c1 83 f8 90 01 01 44 0f 45 c0 49 83 ea 90 01 01 75 90 00 } //1
		$a_03_2 = {47 00 45 00 c7 90 01 02 54 00 00 00 ff 90 00 } //1
		$a_03_3 = {73 00 3a 00 90 02 0a 2f 00 2f 00 e8 90 01 02 00 00 81 3b 68 74 74 70 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule Ransom_Win64_Knight_ZA_MTB_2{
	meta:
		description = "Ransom:Win64/Knight.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 64 61 74 61 20 69 73 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 Your data is stolen and encrypted
		$a_01_1 = {22 6e 6f 74 65 5f 66 69 6c 65 5f 6e 61 6d 65 22 3a 20 22 52 45 41 44 4d 45 5f } //1 "note_file_name": "README_
		$a_01_2 = {68 74 74 70 3a 2f 2f 72 61 6e 73 6f 6d } //1 http://ransom
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 } //1 cmd.exe /c vssadmin.exe Delete
		$a_01_4 = {22 6b 69 6c 6c 5f 73 65 72 76 69 63 65 73 22 3a 20 5b 22 } //1 "kill_services": ["
		$a_01_5 = {22 77 68 69 74 65 5f 66 69 6c 65 73 22 3a 20 5b 22 4e 54 55 53 45 52 2e 44 41 54 22 } //1 "white_files": ["NTUSER.DAT"
		$a_01_6 = {4f 6e 6c 79 20 70 72 6f 63 65 73 73 20 73 6d 62 20 68 6f 73 74 73 20 69 6e 73 69 64 65 20 64 65 66 69 6e 65 64 20 68 6f 73 74 2e 20 2d 68 6f 73 74 } //1 Only process smb hosts inside defined host. -host
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
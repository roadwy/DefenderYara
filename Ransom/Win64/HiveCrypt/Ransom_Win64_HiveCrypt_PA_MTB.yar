
rule Ransom_Win64_HiveCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/HiveCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 14 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 68 69 76 65 63 75 73 74 } //4 http://hivecust
		$a_01_1 = {68 74 74 70 3a 2f 2f 68 69 76 65 6c 65 61 6b 64 62 } //4 http://hiveleakdb
		$a_01_2 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 73 2e 67 6f } //2 encrypt_files.go
		$a_01_3 = {65 72 61 73 65 5f 6b 65 79 2e 67 6f } //1 erase_key.go
		$a_01_4 = {6b 69 6c 6c 5f 70 72 6f 63 65 73 73 65 73 2e 67 6f } //2 kill_processes.go
		$a_01_5 = {72 65 6d 6f 76 65 5f 73 68 61 64 6f 77 5f 63 6f 70 69 65 73 2e 67 6f } //1 remove_shadow_copies.go
		$a_01_6 = {73 74 6f 70 5f 73 65 72 76 69 63 65 73 5f 77 69 6e 64 6f 77 73 2e 67 6f } //1 stop_services_windows.go
		$a_01_7 = {72 65 6d 6f 76 65 5f 69 74 73 65 6c 66 5f 77 69 6e 64 6f 77 73 2e 67 6f } //1 remove_itself_windows.go
		$a_01_8 = {2f 65 6e 63 72 79 70 74 6f 72 2f } //1 /encryptor/
		$a_01_9 = {48 4f 57 5f 54 4f 5f 44 45 43 52 59 50 54 2e 74 78 74 } //2 HOW_TO_DECRYPT.txt
		$a_01_10 = {46 69 6c 65 73 45 6e 63 72 79 70 74 65 64 } //1 FilesEncrypted
		$a_01_11 = {45 6e 63 72 79 70 74 69 6f 6e 53 74 61 72 74 65 64 } //1 EncryptionStarted
		$a_01_12 = {65 6e 63 72 79 70 74 46 69 6c 65 73 47 72 6f 75 70 } //1 encryptFilesGroup
		$a_01_13 = {59 6f 75 72 20 64 61 74 61 20 77 69 6c 6c 20 62 65 20 75 6e 64 65 63 72 79 70 74 61 62 6c 65 } //1 Your data will be undecryptable
		$a_01_14 = {2d 20 44 6f 20 6e 6f 74 20 66 6f 6f 6c 20 79 6f 75 72 73 65 6c 66 2e 20 45 6e 63 72 79 70 74 69 6f 6e 20 68 61 73 20 70 65 72 66 65 63 74 20 73 65 63 72 65 63 79 } //1 - Do not fool yourself. Encryption has perfect secrecy
		$a_01_15 = {2e 45 6e 63 72 79 70 74 46 69 6c 65 73 2e } //2 .EncryptFiles.
		$a_01_16 = {2e 45 6e 63 72 79 70 74 46 69 6c 65 6e 61 6d 65 2e } //2 .EncryptFilename.
		$a_01_17 = {44 2a 73 74 72 75 63 74 20 7b 20 46 20 75 69 6e 74 70 74 72 3b 20 64 61 74 61 20 2a 5b 5d 75 69 6e 74 38 3b 20 73 65 65 64 20 2a 75 69 6e 74 38 3b 20 66 6e 63 20 2a 6d 61 69 6e 2e 64 65 63 46 75 6e 63 20 7d } //2 D*struct { F uintptr; data *[]uint8; seed *uint8; fnc *main.decFunc }
		$a_01_18 = {67 6f 6c 61 6e 67 2e 6f 72 67 2f 78 2f 73 79 73 2f 77 69 6e 64 6f 77 73 2e 67 65 74 53 79 73 74 65 6d 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 } //1 golang.org/x/sys/windows.getSystemWindowsDirectory
		$a_01_19 = {70 61 74 68 2f 66 69 6c 65 70 61 74 68 2e 57 61 6c 6b 44 69 72 } //1 path/filepath.WalkDir
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*2+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*2+(#a_01_16  & 1)*2+(#a_01_17  & 1)*2+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1) >=8
 
}
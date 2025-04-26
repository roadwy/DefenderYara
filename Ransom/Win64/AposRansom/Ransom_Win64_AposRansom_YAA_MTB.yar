
rule Ransom_Win64_AposRansom_YAA_MTB{
	meta:
		description = "Ransom:Win64/AposRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //5 vssadmin Delete Shadows /All /Quiet
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 46 69 6c 65 } //5 powershell -ExecutionPolicy Bypass -File
		$a_01_2 = {45 6e 63 72 79 70 74 48 69 64 64 65 6e 44 69 72 65 63 74 6f 72 69 65 73 } //2 EncryptHiddenDirectories
		$a_01_3 = {43 68 61 6e 67 65 57 61 6c 6c 70 61 70 65 72 } //1 ChangeWallpaper
		$a_01_4 = {75 70 6c 6f 61 64 65 64 20 74 6f 20 6f 75 72 20 73 65 72 76 65 72 73 20 } //1 uploaded to our servers 
		$a_01_5 = {62 61 63 6b 75 70 73 20 61 6e 64 20 73 68 61 64 6f 77 20 63 6f 70 69 65 73 20 68 61 76 65 20 62 65 65 6e 20 63 6f 72 72 75 70 74 65 64 } //1 backups and shadow copies have been corrupted
		$a_01_6 = {73 79 73 74 65 6d 20 75 6e 72 65 63 6f 76 65 72 61 62 6c 65 } //1 system unrecoverable
		$a_01_7 = {66 6f 72 63 65 64 20 74 6f 20 70 75 62 6c 69 73 68 20 79 6f 75 72 20 64 61 74 61 20 6f 6e 6c 69 6e 65 20 } //1 forced to publish your data online 
		$a_01_8 = {70 65 72 6d 61 6e 65 6e 74 6c 79 20 64 61 6d 61 67 65 20 74 68 65 6d } //1 permanently damage them
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=18
 
}

rule Ransom_Win64_Emperor_YBG_MTB{
	meta:
		description = "Ransom:Win64/Emperor.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 69 73 52 61 6e 73 6f 6d 4e 6f 74 65 } //1 main.isRansomNote
		$a_01_1 = {6d 61 69 6e 2e 73 68 6f 75 6c 64 45 6e 63 72 79 70 74 } //1 main.shouldEncrypt
		$a_01_2 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 46 69 6c 65 } //1 main.encryptFile
		$a_01_3 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 44 72 69 76 65 } //1 main.encryptDrive
		$a_01_4 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 41 6c 6c 44 72 69 76 65 73 } //1 main.encryptAllDrives
		$a_01_5 = {67 6f 6c 61 6e 67 } //1 golang
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
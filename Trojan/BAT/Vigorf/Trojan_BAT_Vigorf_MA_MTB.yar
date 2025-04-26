
rule Trojan_BAT_Vigorf_MA_MTB{
	meta:
		description = "Trojan:BAT/Vigorf.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {37 66 62 30 33 63 62 30 2d 66 31 31 37 2d 34 34 32 34 2d 61 63 65 32 2d 35 62 35 39 63 37 33 34 63 35 36 64 } //1 7fb03cb0-f117-4424-ace2-5b59c734c56d
		$a_01_1 = {67 65 74 5f 41 75 74 6f 4b 79 4b 78 } //1 get_AutoKyKx
		$a_01_2 = {4b 59 4b 65 6f 78 65 } //1 KYKeoxe
		$a_01_3 = {67 65 74 5f 61 75 74 6f 70 6b 76 69 70 31 } //1 get_autopkvip1
		$a_01_4 = {53 6c 65 65 70 } //1 Sleep
		$a_01_5 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_6 = {63 68 65 63 6b 46 69 6c 65 54 6f 44 6f 77 6e 6c 6f 61 64 } //1 checkFileToDownload
		$a_01_7 = {47 65 74 46 69 6c 65 4e 61 6d 65 57 69 74 68 6f 75 74 45 78 74 65 6e 73 69 6f 6e } //1 GetFileNameWithoutExtension
		$a_01_8 = {43 72 65 61 74 65 53 68 6f 72 74 63 75 74 } //1 CreateShortcut
		$a_01_9 = {67 65 74 5f 6c 6f 67 69 6e } //1 get_login
		$a_01_10 = {67 65 74 5f 41 75 74 6f 75 70 64 61 74 65 49 4e 49 } //1 get_AutoupdateINI
		$a_01_11 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_12 = {67 65 74 5f 41 75 74 6f 50 4b 46 69 6c 65 } //1 get_AutoPKFile
		$a_01_13 = {46 69 6c 65 53 74 72 65 61 6d } //1 FileStream
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}
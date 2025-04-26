
rule Trojan_BAT_Redlonam_A{
	meta:
		description = "Trojan:BAT/Redlonam.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0a 00 00 "
		
	strings :
		$a_01_0 = {52 6d 39 73 5a 47 56 79 54 6d 46 74 5a 56 78 6d 61 57 78 6c 4c 6d 56 34 5a 51 3d 3d } //1 Rm9sZGVyTmFtZVxmaWxlLmV4ZQ==
		$a_01_1 = {46 6f 6c 64 65 72 4e 61 6d 65 5c 66 69 6c 65 2e 65 78 65 } //1 FolderName\file.exe
		$a_01_2 = {5a 6d 6c 73 5a 53 35 6c 65 47 55 3d } //1 ZmlsZS5leGU=
		$a_01_3 = {66 69 6c 65 2e 65 78 65 } //1 file.exe
		$a_01_4 = {58 48 52 6c 62 58 42 63 } //1 XHRlbXBc
		$a_01_5 = {5c 74 65 6d 70 5c } //1 \temp\
		$a_01_6 = {62 58 6c 54 59 57 78 30 56 6d 46 73 64 57 55 3d } //1 bXlTYWx0VmFsdWU=
		$a_01_7 = {6d 79 53 61 6c 74 56 61 6c 75 65 } //1 mySaltValue
		$a_01_8 = {51 44 46 43 4d 6d 4d 7a 52 44 52 6c 4e 55 59 32 5a 7a 64 49 4f 41 3d 3d } //1 QDFCMmMzRDRlNUY2ZzdIOA==
		$a_01_9 = {40 31 42 32 63 33 44 34 65 35 46 36 67 37 48 38 } //1 @1B2c3D4e5F6g7H8
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=4
 
}
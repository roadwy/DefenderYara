
rule TrojanDownloader_Win32_Spycos_I{
	meta:
		description = "TrojanDownloader:Win32/Spycos.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {26 6d 65 6e 73 61 67 65 6d 3d 00 } //1
		$a_01_1 = {41 56 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 3a 20 4e 4f 52 54 45 00 } //1 噁⸮⸮⸮⸮⸮⸮⸮›低呒E
		$a_03_2 = {50 6c 75 67 69 6e 20 52 45 44 2e 2e 2e 2e 2e 2e 3a 20 90 03 03 07 53 49 4d 41 56 47 49 4e 48 4f 90 00 } //1
		$a_01_3 = {52 45 45 4e 56 49 4f 3d 00 } //1
		$a_01_4 = {5a 41 4c 53 63 37 61 4a 56 6e 53 58 6e 48 30 58 4e 72 2f 76 77 51 3d 3d } //1 ZALSc7aJVnSXnH0XNr/vwQ==
		$a_01_5 = {41 61 32 65 42 73 70 66 59 42 67 73 75 39 55 74 6e 46 35 6e 57 67 3d 3d } //1 Aa2eBspfYBgsu9UtnF5nWg==
		$a_01_6 = {74 2f 4b 62 6c 68 79 35 32 55 36 66 41 43 37 47 6c 44 6a 53 37 65 39 64 77 52 6a 66 59 41 58 59 2f 45 43 65 51 57 6e 5a 48 75 51 3d } //1 t/Kblhy52U6fAC7GlDjS7e9dwRjfYAXY/ECeQWnZHuQ=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=4
 
}
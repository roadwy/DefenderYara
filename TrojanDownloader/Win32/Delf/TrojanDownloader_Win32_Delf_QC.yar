
rule TrojanDownloader_Win32_Delf_QC{
	meta:
		description = "TrojanDownloader:Win32/Delf.QC,SIGNATURE_TYPE_PEHSTR,08 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {45 6e 61 62 6c 65 4c 55 41 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 20 2f 66 } //1 EnableLUA /t REG_DWORD /d 0 /f
		$a_01_1 = {67 6f 6f 67 6c 65 2e 63 6f 6d 2e 62 72 } //1 google.com.br
		$a_01_2 = {54 69 6d 65 72 5f 52 65 67 69 73 74 72 6f 54 69 6d 65 72 } //1 Timer_RegistroTimer
		$a_01_3 = {54 69 6d 65 72 5f 44 6f 77 6e 6c 6f 61 64 54 69 6d 65 72 } //1 Timer_DownloadTimer
		$a_01_4 = {24 28 2c 30 34 38 3c 40 44 48 4c 4c 50 50 54 54 58 58 5c 5c 60 60 64 64 68 68 6c 6c 70 70 74 74 74 74 78 78 78 78 7c 7c 7c 7c } //1 $(,048<@DHLLPPTTXX\\``ddhhllppttttxxxx||||
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_7 = {45 6e 75 6d 43 61 6c 65 6e 64 61 72 49 6e 66 6f 41 } //1 EnumCalendarInfoA
		$a_01_8 = {36 33 45 34 37 35 46 35 37 45 38 36 39 46 41 35 42 43 34 44 44 36 36 44 46 38 30 38 30 33 30 39 30 31 30 32 30 33 30 33 31 43 } //1 63E475F57E869FA5BC4DD66DF8080309010203031C
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}
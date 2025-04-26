
rule TrojanDownloader_Win32_Coinminer_QB_bit{
	meta:
		description = "TrojanDownloader:Win32/Coinminer.QB!bit,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 69 6e 6e 66 69 6e 69 74 69 2e 75 63 6f 7a 2e 6e 65 74 2f [0-10] 2e 7a 69 70 } //3
		$a_03_1 = {46 69 6c 65 44 65 6c 65 74 65 2c 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-10] 2e 76 62 73 } //2
		$a_01_2 = {48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 72 6f 64 75 63 74 4e 61 6d 65 } //2 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 69 70 6c 6f 67 67 65 72 2e 63 6f 6d } //1 https://iplogger.com
		$a_01_4 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 6f 72 } //1 Select * from Win32_Processor
		$a_01_5 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 41 56 41 53 54 20 53 6f 66 74 77 61 72 65 } //1 C:\ProgramData\AVAST Software
		$a_01_6 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 45 53 45 54 } //1 C:\ProgramData\ESET
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}
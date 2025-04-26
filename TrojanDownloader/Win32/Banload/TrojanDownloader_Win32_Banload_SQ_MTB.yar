
rule TrojanDownloader_Win32_Banload_SQ_MTB{
	meta:
		description = "TrojanDownloader:Win32/Banload.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 } //1 If exist "%s" Goto 1
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e } //1 SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 72 61 79 6d 67 72 31 2e 65 78 65 } //1 C:\ProgramData\traymgr1.exe
		$a_01_3 = {68 74 74 70 3a 2f 2f 62 69 74 2e 6c 79 2f 57 70 63 57 4b 66 } //1 http://bit.ly/WpcWKf
		$a_01_4 = {63 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6f 75 74 6c 6f 6f 6b 2e 65 78 65 } //1 c:\ProgramData\outlook.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}

rule TrojanDownloader_Win32_ValleyRat_FG_MTB{
	meta:
		description = "TrojanDownloader:Win32/ValleyRat.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 32 2e 65 78 65 } //1 C:\Windows\WindowsFormsApp2.exe
		$a_00_1 = {43 3a 5c 44 69 73 70 48 65 6c 70 65 72 5c 68 72 2e 65 78 65 } //1 C:\DispHelper\hr.exe
		$a_01_2 = {61 48 52 30 63 44 6f 76 4c 7a 45 7a 4e 43 34 78 4d 6a 49 75 4d 54 59 7a 4c 6a 49 7a 4d 6a 6f 34 4f 44 67 34 4c 32 52 76 64 32 34 76 62 6b 4a 4f 57 6b 78 47 51 6e 6c 45 54 57 35 4f } //1 aHR0cDovLzEzNC4xMjIuMTYzLjIzMjo4ODg4L2Rvd24vbkJOWkxGQnlETW5O
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
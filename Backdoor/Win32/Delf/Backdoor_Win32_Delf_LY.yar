
rule Backdoor_Win32_Delf_LY{
	meta:
		description = "Backdoor:Win32/Delf.LY,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 } //01 00  \Software\Microsoft\Windows\CurrentVersion\Explorer
		$a_01_1 = {72 65 63 65 62 65 72 } //02 00  receber
		$a_01_2 = {4c 6f 67 6f 6e 20 55 73 65 72 20 4e 61 6d 65 } //06 00  Logon User Name
		$a_01_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 5c 62 61 73 69 6c 69 73 63 6f 2e 65 78 65 } //00 00  C:\Windows\System\basilisco.exe
	condition:
		any of ($a_*)
 
}

rule TrojanDownloader_Win32_Delf_NZ{
	meta:
		description = "TrojanDownloader:Win32/Delf.NZ,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_02_1 = {77 2e 32 73 68 61 72 65 64 2e 63 6f 6d 2f 66 69 6c 65 2f 90 02 08 2f 90 02 08 2e 68 74 6d 6c 90 00 } //10
		$a_00_2 = {72 65 67 6e 6f 77 2e 65 78 65 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 6d 73 61 70 70 73 5c 6d 73 69 6e 66 6f 5c 73 61 6e 74 61 30 36 2e 64 6c 6c 20 2f 73 } //10 regnow.exe C:\WINDOWS\msapps\msinfo\santa06.dll /s
		$a_00_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 65 63 75 72 69 74 79 5c 44 61 74 61 62 61 73 65 5c } //1 C:\WINDOWS\security\Database\
		$a_00_4 = {63 6f 75 6e 74 31 2e 6c 6f 67 } //1 count1.log
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=31
 
}
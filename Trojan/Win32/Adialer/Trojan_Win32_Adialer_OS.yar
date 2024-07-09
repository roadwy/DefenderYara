
rule Trojan_Win32_Adialer_OS{
	meta:
		description = "Trojan:Win32/Adialer.OS,SIGNATURE_TYPE_PEHSTR_EXT,19 00 18 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_00_1 = {52 65 61 64 79 20 74 6f 20 63 6f 6e 6e 65 63 74 } //1 Ready to connect
		$a_00_2 = {72 61 73 64 74 5f 69 73 64 6e } //1 rasdt_isdn
		$a_00_3 = {45 52 52 4f 52 5f 43 41 4e 4e 4f 54 5f 4f 50 45 4e 5f 50 48 4f 4e 45 42 4f 4f 4b } //1 ERROR_CANNOT_OPEN_PHONEBOOK
		$a_00_4 = {52 61 73 44 69 61 6c } //1 RasDial
		$a_02_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 72 65 61 78 78 78 2e 62 69 7a 2f 69 76 72 2f 69 6e 64 65 78 ?? 2e 70 68 70 } //10
		$a_00_6 = {b2 46 b3 54 80 bc 04 3c 4f 00 00 43 75 56 38 94 04 3d 4f 00 00 75 4d 80 bc 04 3e 4f 00 00 47 75 43 80 bc 04 3f 4f 00 00 5f 75 39 80 bc 04 40 4f 00 00 4f 75 2f 38 94 04 41 4f 00 00 75 26 38 94 04 42 4f 00 00 75 1d 80 bc 04 43 4f 00 00 53 75 13 80 bc 04 44 4f 00 00 45 75 09 38 9c 04 45 4f 00 00 74 07 40 3b c1 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*10+(#a_00_6  & 1)*10) >=24
 
}
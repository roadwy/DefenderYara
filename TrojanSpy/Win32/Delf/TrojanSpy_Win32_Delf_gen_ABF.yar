
rule TrojanSpy_Win32_Delf_gen_ABF{
	meta:
		description = "TrojanSpy:Win32/Delf.gen!ABF,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {5f 49 45 42 72 6f 77 73 65 72 48 65 6c 70 65 72 } //1 _IEBrowserHelper
		$a_01_2 = {2f 7e 75 73 65 72 31 2f 65 72 72 6f 72 73 2f 64 62 36 2e 70 68 70 3f } //1 /~user1/errors/db6.php?
		$a_01_3 = {26 50 4f 53 54 44 41 54 41 3d 4e 4f 57 } //1 &POSTDATA=NOW
		$a_01_4 = {26 43 4f 4f 4b 49 45 44 41 54 41 3d 4e 4f 57 } //1 &COOKIEDATA=NOW
		$a_01_5 = {26 57 49 4e 44 41 54 41 3d 4e 4f 57 } //1 &WINDATA=NOW
		$a_00_6 = {62 72 6f 77 73 65 72 68 65 6c 70 65 72 2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 } //1
		$a_01_7 = {43 3a 5c 54 45 4d 50 5c 5c } //1 C:\TEMP\\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}

rule Trojan_Win32_Delf_RA{
	meta:
		description = "Trojan:Win32/Delf.RA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {ff 53 0c 83 7e 0c 00 75 0b 81 7e 08 c0 5d 02 00 76 48 eb 02 7e 44 8b 46 08 8b 56 0c 2d c0 5d 02 00 83 da 00 83 fa 00 75 09 3d c0 5d 02 00 77 2a eb 02 } //1
		$a_00_1 = {4d 69 6e 69 6d 69 7a 65 2e 73 63 66 } //1 Minimize.scf
		$a_00_2 = {6e 65 74 20 73 68 61 72 65 } //1 net share
		$a_00_3 = {73 68 61 72 65 61 62 6c 65 20 77 61 69 74 } //1 shareable wait
		$a_00_4 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d } //1 [InternetShortcut]
		$a_00_5 = {6d 63 69 53 65 6e 64 53 74 72 69 6e 67 41 } //1 mciSendStringA
		$a_00_6 = {46 61 73 74 4d 4d 20 42 6f 72 6c 61 6e 64 20 45 64 69 74 69 6f 6e } //1 FastMM Borland Edition
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
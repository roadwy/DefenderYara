
rule Trojan_Win32_Delf_EG{
	meta:
		description = "Trojan:Win32/Delf.EG,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //2 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {75 72 6c 6d 6f 6e 00 00 2e 64 6c 6c 00 } //2
		$a_02_2 = {b8 01 00 00 80 90 02 01 e8 90 01 01 fb ff ff 68 90 01 03 00 ff 15 90 01 04 8d 4d 90 01 01 ba 90 01 02 1b 02 b8 90 01 02 1b 02 e8 90 01 02 ff ff 8b 45 90 01 01 e8 90 01 02 ff ff 8b d0 8d 45 90 00 } //2
		$a_00_3 = {80 3d 10 50 1b 02 01 76 11 6a 00 6a 00 6a 00 68 df fa ed 0e ff 15 } //1
		$a_00_4 = {8d 40 00 85 c9 74 19 8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}
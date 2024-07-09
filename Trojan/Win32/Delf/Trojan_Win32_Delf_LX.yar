
rule Trojan_Win32_Delf_LX{
	meta:
		description = "Trojan:Win32/Delf.LX,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 64 69 73 61 62 6c 65 } //1 netsh firewall set opmode disable
		$a_00_1 = {5c 73 74 61 72 74 20 6d 65 6e 75 5c 70 72 6f 67 72 61 6d 73 5c 73 74 61 72 74 75 70 } //1 \start menu\programs\startup
		$a_00_2 = {72 65 67 73 76 72 33 32 20 2f 73 20 } //1 regsvr32 /s 
		$a_00_3 = {73 6f 66 74 77 61 72 65 5c 62 6f 72 6c 61 6e 64 5c 64 65 6c 70 68 69 5c 6c 6f 63 61 6c 65 73 } //1 software\borland\delphi\locales
		$a_00_4 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73 } //1
		$a_02_5 = {5a 58 85 ff 75 0c 85 d2 74 03 ff 4a f8 e8 ?? ?? ff ff 5a 5f 5e 5b 58 8d 24 94 ff e0 } //1
		$a_01_6 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
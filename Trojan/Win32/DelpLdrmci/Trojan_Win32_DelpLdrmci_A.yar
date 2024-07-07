
rule Trojan_Win32_DelpLdrmci_A{
	meta:
		description = "Trojan:Win32/DelpLdrmci.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 00 01 00 00 53 6a 00 e8 90 01 02 fa ff 90 90 e8 90 01 02 fa ff 80 3b 43 75 1f 80 7b 03 53 75 19 80 7b 05 4c 75 13 80 7b 04 45 75 0d 80 7b 06 46 75 07 6a 00 e8 90 01 02 fa ff 90 00 } //2
		$a_03_1 = {ba d7 88 00 00 31 c9 80 34 01 90 01 01 41 39 d1 75 f7 05 4d 32 00 00 ff e0 90 00 } //2
		$a_00_2 = {6d 63 69 53 65 6e 64 43 6f 6d 6d 61 6e 64 41 } //1 mciSendCommandA
		$a_00_3 = {46 50 55 4d 61 73 6b 56 61 6c 75 65 } //1 FPUMaskValue
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}
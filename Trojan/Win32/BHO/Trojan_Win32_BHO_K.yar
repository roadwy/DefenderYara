
rule Trojan_Win32_BHO_K{
	meta:
		description = "Trojan:Win32/BHO.K,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 07 00 00 "
		
	strings :
		$a_03_0 = {6a 40 33 c0 59 8d bd 90 01 02 ff ff 88 95 90 01 02 ff ff 68 3f 00 0f 00 f3 ab 66 ab 68 90 01 04 68 02 00 00 80 8d 90 01 02 89 90 01 02 c7 90 01 02 04 01 00 00 aa 90 00 } //10
		$a_02_1 = {69 65 67 75 69 64 65 2e 63 6f 2e 6b 72 2f 90 02 20 2e 70 68 70 3f 90 00 } //2
		$a_00_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 69 65 67 75 69 64 65 5f 70 6c 75 73 5c 57 53 6f 63 6b 2e 64 6c 6c } //2 C:\Program Files\ieguide_plus\WSock.dll
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 69 65 67 75 69 64 65 5f 70 6c 75 73 } //2 SOFTWARE\ieguide_plus
		$a_00_4 = {69 65 67 75 69 64 65 6b 65 79 77 6f 72 64 } //1 ieguidekeyword
		$a_00_5 = {53 74 61 72 74 44 6c 6c } //1 StartDll
		$a_00_6 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //1 Internet Explorer_Server
	condition:
		((#a_03_0  & 1)*10+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=18
 
}
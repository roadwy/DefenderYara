
rule Trojan_Win32_Startpage_AFZ{
	meta:
		description = "Trojan:Win32/Startpage.AFZ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_00_0 = {5c 46 69 6c 6d 2e 69 63 6f } //1 \Film.ico
		$a_00_1 = {5c 6d 65 69 76 2e 69 63 6f } //1 \meiv.ico
		$a_00_2 = {5c 42 65 61 75 74 79 2e 69 63 6f } //1 \Beauty.ico
		$a_00_3 = {33 36 30 73 64 2e 65 78 65 00 33 36 30 74 72 61 79 2e 65 78 65 00 51 51 44 6f 63 74 6f 72 52 74 70 2e 65 78 65 00 52 61 76 2e 65 78 65 00 77 78 43 6c 74 41 69 64 2e 65 78 65 00 61 76 70 2e 65 78 65 00 6b 77 73 74 72 61 79 2e 65 78 65 } //2
		$a_02_4 = {65 63 68 6f 20 79 7c 20 63 61 63 6c 73 20 22 [0-15] 2e 75 72 6c 22 [0-04] 2f 70 20 65 76 65 72 79 6f 6e 65 3a 66 } //2
		$a_02_5 = {5c 6b 77 73 2e 69 6e 69 22 [0-04] 2b 52 20 2b 53 } //2
		$a_02_6 = {5c 6b 77 73 2e 69 6e 69 22 [0-04] 2f 70 20 65 76 65 72 79 6f 6e 65 3a 52 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_02_4  & 1)*2+(#a_02_5  & 1)*2+(#a_02_6  & 1)*2) >=8
 
}
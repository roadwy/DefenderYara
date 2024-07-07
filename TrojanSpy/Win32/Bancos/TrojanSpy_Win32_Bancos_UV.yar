
rule TrojanSpy_Win32_Bancos_UV{
	meta:
		description = "TrojanSpy:Win32/Bancos.UV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {31 43 6c 69 63 6b 13 00 90 02 08 49 6d 61 67 65 90 10 03 00 43 6c 69 63 6b 90 00 } //1
		$a_00_1 = {65 6d 61 69 6c 3d 6d 65 6c 68 6f 72 61 74 65 72 63 61 66 65 69 72 61 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //1 email=melhoratercafeira@hotmail.com
		$a_02_2 = {66 72 6f 6d 3d 78 78 78 40 69 6e 66 6f 2e 63 6f 6d 90 02 20 73 75 62 6a 65 63 74 3d 90 02 20 6d 65 73 73 61 67 65 3d 90 00 } //1
		$a_00_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 6f 65 74 73 70 6c 61 7a 61 2e 6e 6c 2f 70 61 73 63 61 6c 2f 69 6e 64 65 78 2e 70 68 70 } //1 http://www.toetsplaza.nl/pascal/index.php
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
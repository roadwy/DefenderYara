
rule Trojan_Win32_Reposin_A{
	meta:
		description = "Trojan:Win32/Reposin.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 08 00 00 "
		
	strings :
		$a_02_0 = {e9 ad 00 00 00 8b 45 e4 2b c2 8b c8 bf 90 01 02 40 00 8b f2 33 db f3 a6 75 1c 6a 19 ff 75 f8 ff 75 f4 90 00 } //8
		$a_00_1 = {8b 74 24 08 57 8b f9 eb 0f 8a 0e 8a 07 8a d0 32 c1 02 d1 88 06 88 17 46 3b 74 24 10 72 eb } //5
		$a_01_2 = {66 69 6c 65 6e 61 6d 65 3d 22 69 6d 61 67 2e 6a 70 67 22 } //2 filename="imag.jpg"
		$a_01_3 = {66 69 6c 65 6e 61 6d 65 3d 20 22 6c 69 6e 6b 73 2e 61 72 63 68 22 } //2 filename= "links.arch"
		$a_01_4 = {2d 2d 4b 6b 4b 31 37 5f 7a 5a 41 32 31 } //1 --KkK17_zZA21
		$a_01_5 = {64 69 72 65 63 74 2e 70 61 6e 78 66 69 73 65 61 72 63 68 6d 61 73 6e 61 6d 65 73 2e 63 6f 6d } //1 direct.panxfisearchmasnames.com
		$a_01_6 = {74 72 75 73 74 2e 63 65 6c 6c 78 6d 61 74 65 74 72 61 76 65 6c 78 61 70 73 69 6e 66 6f 2e 63 6f 6d } //1 trust.cellxmatetravelxapsinfo.com
		$a_01_7 = {6c 6f 6f 6b 20 61 74 74 61 63 68 6d 65 6e 74 } //1 look attachment
	condition:
		((#a_02_0  & 1)*8+(#a_00_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}
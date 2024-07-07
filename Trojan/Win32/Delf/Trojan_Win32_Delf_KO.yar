
rule Trojan_Win32_Delf_KO{
	meta:
		description = "Trojan:Win32/Delf.KO,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 6f 73 6f 2e 63 6f 6d 2f 71 3f 77 3d 25 73 26 6c 72 3d 26 73 63 3d 77 65 62 26 63 68 3d 77 2e 70 26 66 69 6c 74 65 72 3d 31 26 6e 75 6d 3d 31 30 26 70 67 3d 25 64 } //2 http://www.soso.com/q?w=%s&lr=&sc=web&ch=w.p&filter=1&num=10&pg=%d
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 73 65 61 72 63 68 3f 63 6f 6d 70 6c 65 74 65 3d 31 26 71 3d 25 73 } //2 http://www.google.com/search?complete=1&q=%s
		$a_01_2 = {54 41 64 73 49 6e 66 6f 34 } //2 TAdsInfo4
		$a_01_3 = {7a 5f 68 73 74 65 6d 70 25 2e 33 64 2e 68 74 6d 6c } //3 z_hstemp%.3d.html
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3) >=9
 
}

rule Trojan_Win32_Delf_RRB{
	meta:
		description = "Trojan:Win32/Delf.RRB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 78 2d 21 40 23 24 78 78 } //1 xx-!@#$xx
		$a_01_1 = {3c 69 66 72 61 6d 65 20 73 72 63 3d 22 68 74 74 70 3a 2f 2f 6c 6f 63 61 6c 68 6f 73 74 3a 39 37 2f 61 2e 68 74 6d 22 20 2f 3e } //1 <iframe src="http://localhost:97/a.htm" />
		$a_01_2 = {5f 6a 64 66 77 6b 65 79 3d 63 77 25 64 7c 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6b 36 36 2e 63 6e 2f } //1 _jdfwkey=cw%d|http://www.gk66.cn/
		$a_03_3 = {24 24 61 2e 62 61 74 90 01 09 3a 74 72 79 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
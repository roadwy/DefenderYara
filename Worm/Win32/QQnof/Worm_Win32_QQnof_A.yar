
rule Worm_Win32_QQnof_A{
	meta:
		description = "Worm:Win32/QQnof.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {6a 00 50 6a 00 6a 00 ff d3 68 ff 01 00 00 ff 15 90 01 04 68 90 00 } //10
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 72 6a 68 6f 75 74 61 69 2e 63 6e } //1 http://www.rjhoutai.cn
		$a_00_2 = {68 74 74 70 3a 2f 2f 75 73 65 72 2e 71 62 61 72 2e 71 71 2e 63 6f 6d 2f } //1 http://user.qbar.qq.com/
		$a_00_3 = {68 74 74 70 3a 2f 2f 6d 69 6e 69 73 69 74 65 2e 71 71 2e 63 6f 6d 2f 61 6c 6c 2f 61 6c 6c 69 6e 6f 6e 65 2e 73 68 74 6d 6c } //1 http://minisite.qq.com/all/allinone.shtml
		$a_00_4 = {26 61 6c 65 78 61 3d 00 26 6c 69 61 6e 6d 65 6e 67 3d 00 00 26 6d 61 63 3d 00 00 00 26 76 65 72 3d 00 00 00 69 6e 73 74 61 6c 6c 00 61 63 74 69 6f 6e 3d 00 2f 68 61 69 6c 69 61 6e 67 2e 61 73 70 78 3f 00 47 4f 4f 47 4c 45 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*10) >=21
 
}
rule Worm_Win32_QQnof_A_2{
	meta:
		description = "Worm:Win32/QQnof.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4e 20 8b 3d a8 21 40 00 6a 00 6a 64 68 d8 00 00 00 51 ff d7 8b 56 20 6a 00 6a 64 68 cf 00 00 00 52 ff d7 } //1
		$a_01_1 = {62 69 61 6f 6a 69 00 00 4e 6f 74 69 66 79 57 6e 64 00 00 00 d6 d8 c6 f4 c7 b0 b6 d4 b8 c3 cf ee b2 c9 d3 c3 cf e0 cd ac b2 d9 d7 f7 2c b2 bb d4 d9 bd f8 d0 d0 cc e1 ca be 00 00 00 b2 a2 bd ab c6 e4 bc d3 c8 eb d0 c5 c8 ce b2 e5 bc fe c1 d0 b1 ed } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
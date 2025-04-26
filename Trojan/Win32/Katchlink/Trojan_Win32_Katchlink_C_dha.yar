
rule Trojan_Win32_Katchlink_C_dha{
	meta:
		description = "Trojan:Win32/Katchlink.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 73 61 66 65 5f 33 32 2e 64 6c 6c 00 70 72 6f 74 65 63 74 } //3 楷獮晡彥㈳搮汬瀀潲整瑣
		$a_01_1 = {77 69 6e 73 61 66 65 5f 36 34 2e 64 6c 6c 00 70 72 6f 74 65 63 74 } //3 楷獮晡彥㐶搮汬瀀潲整瑣
		$a_01_2 = {47 6c 6f 62 61 6c 5c 77 6f 77 00 } //1
		$a_01_3 = {6f 70 65 6e 20 66 69 6c 65 20 65 72 72 6f 72 5c 6e 65 72 72 6f 72 20 63 6f 64 65 3a 25 64 } //1 open file error\nerror code:%d
		$a_01_4 = {72 65 61 64 20 6c 65 6e 74 68 20 3a 25 64 2c 72 65 74 75 72 6e 20 76 61 6c 75 65 3a 25 64 } //1 read lenth :%d,return value:%d
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}
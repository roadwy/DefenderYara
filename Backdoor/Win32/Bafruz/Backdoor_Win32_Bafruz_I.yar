
rule Backdoor_Win32_Bafruz_I{
	meta:
		description = "Backdoor:Win32/Bafruz.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {64 64 6f 73 5f 68 74 74 70 5f 6c 69 73 74 } //2 ddos_http_list
		$a_00_1 = {4b 41 56 5f 53 54 41 52 54 } //1 KAV_START
		$a_01_2 = {73 74 61 6e 64 00 00 00 6f 70 65 6e 00 } //1
		$a_03_3 = {b9 40 42 0f 00 ba 95 b2 00 00 b8 90 01 03 00 e8 90 01 03 ff 84 c0 75 90 00 } //1
		$a_01_4 = {77 5f 64 69 73 74 72 69 62 5f 69 70 6c 69 73 74 2e 74 78 74 } //1 w_distrib_iplist.txt
		$a_03_5 = {ff 52 14 83 f8 0a 7d 90 01 01 6a 50 68 10 27 00 00 6a 01 6a 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}
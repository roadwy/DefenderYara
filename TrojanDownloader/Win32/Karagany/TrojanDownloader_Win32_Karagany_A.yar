
rule TrojanDownloader_Win32_Karagany_A{
	meta:
		description = "TrojanDownloader:Win32/Karagany.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {7e 1b 8a 55 0c 8b 45 08 02 d1 30 14 30 83 f9 03 7e 04 33 c9 eb 01 41 46 3b 75 10 7c e5 33 c0 40 5e 5d c3 } //3
		$a_01_1 = {68 7c 62 72 78 77 6b 6a 73 2a } //1 h|brxwkjs*
		$a_01_2 = {65 6e 62 70 75 6f 61 74 70 3c 6d 60 3e 72 71 } //1 enbpuoatp<m`>rq
		$a_01_3 = {7a 7d 3f 69 75 6f 7b 75 3f 62 66 7f } //1 絺椿潵畻房罦
		$a_01_4 = {65 64 65 7f 7c 77 21 73 7e 7f } //1 摥罥睼猡罾
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}
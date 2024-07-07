
rule TrojanDownloader_Win32_Cutwail_Q{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.Q,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 6c 64 72 6e 74 2e 62 69 6e 00 } //4
		$a_01_1 = {68 74 74 70 3a 2f 2f 25 73 3a 25 75 2f 73 78 5f 25 75 5f 25 75 5f 25 73 5f 25 73 3f 00 } //1
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 3a 25 75 2f 73 78 5f 25 75 5f 25 75 5f 25 73 00 } //1
		$a_01_3 = {68 74 74 70 3a 2f 2f 25 73 3a 25 75 2f 73 62 5f 25 75 5f 25 75 3f 00 } //1
		$a_01_4 = {68 74 74 70 3a 2f 2f 25 73 3a 25 75 2f 73 62 5f 25 75 5f 25 75 00 } //1 瑨灴⼺┯㩳甥猯形甥╟u
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
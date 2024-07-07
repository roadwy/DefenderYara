
rule Backdoor_Win32_Blohi_gen_C{
	meta:
		description = "Backdoor:Win32/Blohi.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 00 6c 00 6f 00 67 00 2e 00 6e 00 61 00 76 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 50 00 6f 00 73 00 74 00 56 00 69 00 65 00 77 00 2e 00 6e 00 68 00 6e 00 } //5 blog.naver.com/PostView.nhn
		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 61 00 6c 00 20 00 49 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 22 00 } //5 Internetal IExplore"
		$a_01_2 = {6a 56 51 ff d6 8d 55 ac 6a 4d 52 ff d6 8d 45 8c 6a 57 50 ff d6 8d 8d 6c ff ff ff 6a 41 51 ff d6 8d 95 4c ff ff ff 6a 52 52 ff d6 8d 85 2c ff ff ff 6a 45 50 ff d6 } //1
		$a_01_3 = {6a 46 50 ff d6 8d 4d cc 6a 69 51 ff d6 8d 55 ac 6a 6c 52 ff d6 8d 45 8c 6a 65 50 ff d6 8d 8d 6c ff ff ff 6a 55 51 ff d6 8d 95 4c ff ff ff 6a 72 } //1
		$a_01_4 = {66 72 6d 52 65 6d 6f 74 65 53 76 72 00 } //1
		$a_01_5 = {53 74 6f 70 43 6c 69 65 6e 74 49 00 } //1 瑓灯汃敩瑮I
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}

rule TrojanSpy_Win32_Agent_DF{
	meta:
		description = "TrojanSpy:Win32/Agent.DF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6d 67 72 65 2e 65 78 65 } //2 taskmgre.exe
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 } //1 taskkill /im 
		$a_01_2 = {79 76 78 63 63 63 63 63 63 63 63 63 7a 7a 7a 7a 7a 7a 7a 7a 7a 7a 63 63 63 63 63 } //6 yvxccccccccczzzzzzzzzzccccc
		$a_01_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 72 76 3a 38 2e 30 2e 31 29 20 47 65 63 6b 6f 2f 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6f 78 2f 38 2e 30 2e 31 } //1 User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:8.0.1) Gecko/20100101 Firefox/8.0.1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*6+(#a_01_3  & 1)*1) >=10
 
}
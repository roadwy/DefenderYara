
rule Backdoor_Win32_Bafruz_O{
	meta:
		description = "Backdoor:Win32/Bafruz.O,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_03_0 = {6a 50 68 10 27 00 00 6a 01 6a 00 8d ?? ?? 50 8d ?? ?? b8 ?? ?? ?? ?? e8 } //1
		$a_03_1 = {67 65 74 5f 69 70 5f 70 61 79 5f 6e 65 65 64 62 6c 6f 63 6b [0-05] 2e 70 68 70 } //2
		$a_01_2 = {69 65 63 68 65 63 6b 5f 69 70 6c 69 73 74 2e 74 78 74 } //1 iecheck_iplist.txt
		$a_01_3 = {73 72 76 69 65 63 68 65 63 6b } //1 srviecheck
		$a_01_4 = {54 56 4b 5f 57 65 62 53 65 72 76 65 72 } //1 TVK_WebServer
		$a_01_5 = {64 6e 73 2f 64 6e 73 2e 65 78 65 } //1 dns/dns.exe
		$a_01_6 = {69 65 63 68 65 63 6b } //1 iecheck
		$a_01_7 = {31 32 37 2e 30 2e 30 2e 31 20 77 77 77 2e 6c 6f 67 69 6e 2e 76 6b 2e 63 6f 6d } //1 127.0.0.1 www.login.vk.com
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}

rule Trojan_Win32_MalGen_C{
	meta:
		description = "Trojan:Win32/MalGen.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 20 61 74 20 4c 20 25 64 } //1 A at L %d
		$a_01_1 = {74 63 70 69 70 5f 74 68 72 65 61 64 } //1 tcpip_thread
		$a_01_2 = {32 30 38 2e 36 37 2e 32 32 32 2e 32 32 32 } //1 208.67.222.222
		$a_01_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 33 3b 20 57 4f 57 36 34 29 20 41 70 70 6c 65 57 65 62 4b 69 74 2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20 6c 69 6b 65 20 47 65 63 6b 6f 29 20 43 68 72 6f 6d 65 2f 35 37 2e 30 2e 32 39 38 37 2e 31 33 33 20 53 61 66 61 72 69 2f 35 33 37 2e 33 36 } //1 User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
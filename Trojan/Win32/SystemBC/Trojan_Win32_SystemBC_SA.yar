
rule Trojan_Win32_SystemBC_SA{
	meta:
		description = "Trojan:Win32/SystemBC.SA,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 c0 19 73 1e 00 05 43 55 fb 3c c1 d8 10 03 c1 85 d2 } //10
		$a_01_1 = {48 69 c0 19 73 1e 00 48 05 43 55 fb 3c 48 c1 d8 10 48 03 c1 48 85 d2 } //10
		$a_01_2 = {42 45 47 49 4e 44 41 54 41 } //1 BEGINDATA
		$a_01_3 = {48 4f 53 54 31 3a } //1 HOST1:
		$a_01_4 = {50 4f 52 54 31 3a } //1 PORT1:
		$a_01_5 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 57 69 6e 36 34 3b 20 78 36 34 3b 20 72 76 3a 36 36 2e 30 29 } //1 User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0)
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}
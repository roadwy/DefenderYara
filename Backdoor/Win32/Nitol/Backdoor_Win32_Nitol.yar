
rule Backdoor_Win32_Nitol{
	meta:
		description = "Backdoor:Win32/Nitol,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 78 79 2d 61 67 65 6e 74 3a 20 42 65 69 6a 69 50 72 6f 78 79 } //1 Proxy-agent: BeijiProxy
		$a_01_1 = {48 65 61 72 74 62 65 61 74 } //1 Heartbeat
		$a_01_2 = {25 73 69 61 73 2e 69 6e 69 } //1 %sias.ini
		$a_01_3 = {25 73 77 75 61 70 69 2e 69 6e 69 } //1 %swuapi.ini
		$a_01_4 = {25 34 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 } //1 %4d-%02d-%02d %02d:%02d:%02d
		$a_01_5 = {50 72 6f 78 79 57 61 69 74 65 72 7c } //1 ProxyWaiter|
		$a_01_6 = {4f 70 65 6e 57 65 62 } //1 OpenWeb
		$a_01_7 = {50 72 6f 78 79 54 6f 42 61 64 43 6c 6f 73 65 } //1 ProxyToBadClose
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
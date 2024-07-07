
rule Trojan_Win32_Keylogger_PA_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.PA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 68 65 20 4b 65 79 6c 6f 67 67 65 72 20 68 61 73 20 62 65 65 6e 20 69 6e 73 74 61 6c 6c 65 64 } //1 The Keylogger has been installed
		$a_01_1 = {25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 54 4d 6f 6e 69 74 6f 72 5c } //1 %ProgramFiles%\TMonitor\
		$a_01_2 = {77 77 77 2e 4d 79 4b 65 79 6c 6f 67 67 65 72 4f 6e 6c 69 6e 65 2e 63 6f 6d } //1 www.MyKeyloggerOnline.com
		$a_01_3 = {57 69 6e 64 6f 77 73 20 54 61 73 6b 20 4d 6f 6e 69 74 6f 72 2e 6c 6e 6b } //1 Windows Task Monitor.lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
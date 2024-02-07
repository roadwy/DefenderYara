
rule Backdoor_Win32_Nitol{
	meta:
		description = "Backdoor:Win32/Nitol,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 78 79 2d 61 67 65 6e 74 3a 20 42 65 69 6a 69 50 72 6f 78 79 } //01 00  Proxy-agent: BeijiProxy
		$a_01_1 = {48 65 61 72 74 62 65 61 74 } //01 00  Heartbeat
		$a_01_2 = {25 73 69 61 73 2e 69 6e 69 } //01 00  %sias.ini
		$a_01_3 = {25 73 77 75 61 70 69 2e 69 6e 69 } //01 00  %swuapi.ini
		$a_01_4 = {25 34 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 } //01 00  %4d-%02d-%02d %02d:%02d:%02d
		$a_01_5 = {50 72 6f 78 79 57 61 69 74 65 72 7c } //01 00  ProxyWaiter|
		$a_01_6 = {4f 70 65 6e 57 65 62 } //01 00  OpenWeb
		$a_01_7 = {50 72 6f 78 79 54 6f 42 61 64 43 6c 6f 73 65 } //00 00  ProxyToBadClose
	condition:
		any of ($a_*)
 
}
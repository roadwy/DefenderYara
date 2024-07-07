
rule Trojan_Win32_CoinMiner_J{
	meta:
		description = "Trojan:Win32/CoinMiner.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 73 63 6f 6d 6f 73 63 2e 65 78 65 } //1 mscomosc.exe
		$a_01_1 = {74 63 70 3a 2f 2f 70 6f 6f 6c 2e 6d 69 6e 65 78 6d 72 2e 63 6f 6d 3a } //1 tcp://pool.minexmr.com:
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 66 20 2f 69 6d 20 6d 73 63 6f 6d 73 79 73 2e 65 78 65 } //1 cmd.exe /c taskkill.exe /f /im mscomsys.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule Trojan_Win32_Coroxy_BL_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.BL!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {73 6f 63 6b 73 35 } //1 socks5
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 } //1 powershell.exe -windowstyle hidden -Command
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
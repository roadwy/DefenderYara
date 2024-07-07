
rule Trojan_Win32_Coroxy_XZ_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 4f 53 54 31 3a 39 34 2e 31 35 36 2e 36 39 2e 31 30 39 } //1 HOST1:94.156.69.109
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 5c 4d 69 63 72 6f 73 6f 66 74 5c 5c 57 69 6e 64 6f 77 73 5c 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 5c 52 75 6e } //1 Software\\Microsoft\\Windows\\CurrentVersion\\Run
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 } //1 powershell.exe -windowstyle hidden -Command
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}

rule Trojan_Win32_FakeNore{
	meta:
		description = "Trojan:Win32/FakeNore,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 63 00 61 00 6e 00 20 00 69 00 6e 00 20 00 70 00 72 00 6f 00 67 00 72 00 65 00 73 00 73 00 } //1 Scan in progress
		$a_01_1 = {53 00 63 00 61 00 6e 00 20 00 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 } //1 Scan complete
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 63 00 2d 00 73 00 63 00 61 00 6e 00 2d 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 6c 00 32 00 2e 00 70 00 68 00 70 00 3f 00 74 00 3d 00 } //1 http://pc-scan-online.com/l2.php?t=
		$a_01_3 = {43 00 3a 00 5c 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 } //1 C:\NetworkControl
		$a_01_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 35 00 2e 00 32 00 33 00 34 00 2e 00 31 00 39 00 31 00 2e 00 } //1 http://85.234.191.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_FakeNore_2{
	meta:
		description = "Trojan:Win32/FakeNore,SIGNATURE_TYPE_PEHSTR,07 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 } //1 Software\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 35 00 2e 00 32 00 33 00 34 00 2e 00 31 00 39 00 31 00 2e 00 31 00 37 00 30 00 2f 00 69 00 6e 00 73 00 74 00 2e 00 70 00 68 00 70 00 3f 00 69 00 64 00 3d 00 } //3 http://85.234.191.170/inst.php?id=
		$a_01_2 = {43 00 3a 00 5c 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 6e 00 63 00 2e 00 65 00 78 00 65 00 } //2 C:\NetworkControl\nc.exe
		$a_01_3 = {70 00 6f 00 73 00 73 00 69 00 62 00 6c 00 65 00 20 00 74 00 68 00 72 00 65 00 61 00 74 00 73 00 20 00 6f 00 6e 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 2e 00 } //1 possible threats on your computer.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=4
 
}
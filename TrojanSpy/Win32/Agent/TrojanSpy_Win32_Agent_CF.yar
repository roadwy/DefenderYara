
rule TrojanSpy_Win32_Agent_CF{
	meta:
		description = "TrojanSpy:Win32/Agent.CF,SIGNATURE_TYPE_PEHSTR,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {62 75 69 6c 64 20 66 6f 72 20 54 72 6f 6a 61 6e 2e 65 78 65 20 56 65 72 73 69 6f 6e } //1 build for Trojan.exe Version
		$a_01_1 = {3c 77 69 6e 64 69 72 3e 5c 61 76 73 68 6c 64 2e 65 78 65 } //1 <windir>\avshld.exe
		$a_01_2 = {5c 53 6f 66 74 77 61 72 65 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c } //1 \Software\Internet Explorer\
		$a_01_3 = {3c 77 69 6e 64 69 72 3e 5c 6e 76 70 2e 65 78 65 } //1 <windir>\nvp.exe
		$a_01_4 = {3c 77 69 6e 64 69 72 3e 5c 61 76 75 70 64 74 2e 65 78 65 } //1 <windir>\avupdt.exe
		$a_01_5 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c } //1 \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\
		$a_01_6 = {62 65 72 77 61 63 68 74 20 64 65 6e 20 53 79 73 74 65 6d 73 74 61 72 74 } //1 berwacht den Systemstart
		$a_01_7 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 5c 00 00 00 22 00 22 20 65 78 65 63 75 74 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}
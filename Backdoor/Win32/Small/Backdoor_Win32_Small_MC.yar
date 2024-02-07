
rule Backdoor_Win32_Small_MC{
	meta:
		description = "Backdoor:Win32/Small.MC,SIGNATURE_TYPE_PEHSTR,20 00 20 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 73 79 73 6d 6f 6e 2e 65 78 65 } //0a 00  \sysmon.exe
		$a_01_1 = {77 77 77 2e 72 69 6e 67 7a 2e 6f 72 67 } //0a 00  www.ringz.org
		$a_01_2 = {62 61 63 6b 64 6f 6f 72 20 77 72 69 74 74 65 6e 20 62 79 } //01 00  backdoor written by
		$a_01_3 = {57 53 41 53 6f 63 6b 65 74 41 } //01 00  WSASocketA
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}
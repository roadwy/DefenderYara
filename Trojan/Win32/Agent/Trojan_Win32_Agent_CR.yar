
rule Trojan_Win32_Agent_CR{
	meta:
		description = "Trojan:Win32/Agent.CR,SIGNATURE_TYPE_PEHSTR,34 00 32 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 75 70 65 72 48 69 64 64 65 6e } //0a 00  SuperHidden
		$a_01_1 = {2f 63 20 64 65 6c 20 43 3a 5c 6d 79 61 70 70 2e 65 78 65 20 3e 20 6e 75 6c } //0a 00  /c del C:\myapp.exe > nul
		$a_01_2 = {46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 68 00 65 00 63 00 6b 00 } //0a 00  Framework Microsoft Check
		$a_01_3 = {5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 73 00 65 00 72 00 76 00 5c 00 73 00 79 00 73 00 65 00 63 00 63 00 2e 00 65 00 78 00 65 00 } //0a 00  \microsoft\serv\sysecc.exe
		$a_01_4 = {66 00 6f 00 74 00 6f 00 20 00 70 00 6f 00 72 00 6e 00 6f 00 67 00 72 00 61 00 66 00 69 00 63 00 68 00 65 00 20 00 64 00 61 00 20 00 73 00 63 00 61 00 72 00 69 00 63 00 61 00 72 00 65 00 } //01 00  foto pornografiche da scaricare
		$a_01_5 = {52 61 73 44 69 61 6c 41 } //01 00  RasDialA
		$a_01_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //00 00  ShellExecuteExA
	condition:
		any of ($a_*)
 
}
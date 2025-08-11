
rule Trojan_Win64_LummaStealer_NR_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0c 00 00 "
		
	strings :
		$a_02_0 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 20 22 [0-2f] 2e 65 78 65 22 20 2d 46 6f 72 63 65 } //2
		$a_01_1 = {42 45 78 70 6c 6f 72 65 72 20 4c 61 75 6e 63 68 65 72 } //2 BExplorer Launcher
		$a_01_2 = {45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 52 65 61 64 20 61 66 74 65 72 20 43 6c 6f 73 65 } //1 ExecutionPolicyRead after Close
		$a_01_3 = {31 32 37 2e 30 2e 30 2e 31 3a 35 33 } //1 127.0.0.1:53
		$a_01_4 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_01_5 = {42 79 70 61 73 73 48 69 64 64 65 6e } //1 BypassHidden
		$a_01_6 = {43 6f 6d 6d 61 6e 64 } //1 Command
		$a_01_7 = {48 69 64 64 65 6e } //1 Hidden
		$a_01_8 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_01_9 = {4b 65 79 4c 6f 67 57 72 69 74 65 72 } //1 KeyLogWriter
		$a_01_10 = {68 61 6e 67 75 70 6b 69 6c 6c 65 64 } //1 hangupkilled
		$a_01_11 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=14
 
}
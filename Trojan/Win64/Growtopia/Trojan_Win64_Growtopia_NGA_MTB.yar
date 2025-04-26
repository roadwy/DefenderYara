
rule Trojan_Win64_Growtopia_NGA_MTB{
	meta:
		description = "Trojan:Win64/Growtopia.NGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 61 67 6c 61 6e 74 69 20 68 61 74 61 73 69 21 } //1 Baglanti hatasi!
		$a_01_1 = {4b 75 6c 6f 20 50 72 6f 78 79 2e 70 64 62 } //1 Kulo Proxy.pdb
		$a_01_2 = {33 62 61 70 6f 79 38 52 48 31 } //1 3bapoy8RH1
		$a_01_3 = {43 6f 6e 6e 65 63 74 69 6e 67 20 74 6f 20 50 72 6f 78 79 20 53 65 72 76 65 72 2e 2e 2e } //1 Connecting to Proxy Server...
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
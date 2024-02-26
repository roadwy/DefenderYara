
rule Trojan_Win64_Growtopia_NGA_MTB{
	meta:
		description = "Trojan:Win64/Growtopia.NGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 61 67 6c 61 6e 74 69 20 68 61 74 61 73 69 21 } //01 00  Baglanti hatasi!
		$a_01_1 = {4b 75 6c 6f 20 50 72 6f 78 79 2e 70 64 62 } //01 00  Kulo Proxy.pdb
		$a_01_2 = {33 62 61 70 6f 79 38 52 48 31 } //01 00  3bapoy8RH1
		$a_01_3 = {43 6f 6e 6e 65 63 74 69 6e 67 20 74 6f 20 50 72 6f 78 79 20 53 65 72 76 65 72 2e 2e 2e } //01 00  Connecting to Proxy Server...
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00  ShellExecuteA
	condition:
		any of ($a_*)
 
}
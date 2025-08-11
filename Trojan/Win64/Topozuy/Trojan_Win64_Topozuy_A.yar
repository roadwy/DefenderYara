
rule Trojan_Win64_Topozuy_A{
	meta:
		description = "Trojan:Win64/Topozuy.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {66 42 59 6c 58 46 31 4d 62 44 59 6d 54 68 30 74 5a 51 3d 3d } //2 fBYlXF1MbDYmTh0tZQ==
		$a_01_1 = {00 52 78 67 77 58 6c 63 55 00 } //2 刀杸塷捬U
		$a_01_2 = {64 65 63 72 79 70 74 52 4b 4e 53 74 37 } //1 decryptRKNSt7
		$a_01_3 = {6c 61 75 6e 63 68 54 6f 72 52 4b 4e 53 74 37 } //1 launchTorRKNSt7
		$a_01_4 = {70 72 65 70 72 6f 63 65 73 73 65 64 5f 74 72 69 61 67 65 } //1 preprocessed_triage
		$a_01_5 = {63 68 65 63 6b 4e 65 74 77 6f 72 6b 41 64 61 70 74 65 72 4d 61 63 } //1 checkNetworkAdapterMac
		$a_01_6 = {63 68 65 63 6b 56 6d 50 72 6f 63 65 73 73 65 73 } //1 checkVmProcesses
		$a_01_7 = {68 61 73 48 79 70 65 72 76 69 73 6f 72 43 70 75 46 6c 61 67 } //1 hasHypervisorCpuFlag
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}
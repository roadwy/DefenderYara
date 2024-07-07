
rule Backdoor_Win32_Bifrose_gen_B{
	meta:
		description = "Backdoor:Win32/Bifrose.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 07 00 0d 00 00 "
		
	strings :
		$a_00_0 = {4e 6f 72 73 65 20 4d 79 74 68 6f 6c 6f 67 79 2c 20 42 69 66 72 6f 73 74 20 42 72 69 64 67 65 } //1 Norse Mythology, Bifrost Bridge
		$a_00_1 = {67 75 61 72 64 69 61 6e 20 69 73 20 74 68 65 20 67 6f 64 20 48 65 69 6d 64 61 6c 6c 2e } //1 guardian is the god Heimdall.
		$a_00_2 = {4c 69 73 74 65 6e 69 6e 67 20 6f 6e 20 70 6f 72 74 20 25 31 21 } //1 Listening on port %1!
		$a_00_3 = {75 63 63 65 73 73 66 75 6c 6c 79 20 6b 69 6c 6c 65 64 20 70 72 6f 63 65 73 73 } //1 uccessfully killed process
		$a_00_4 = {3c 52 61 6d 64 69 73 6b 3e 00 00 00 3c 52 65 6d } //1
		$a_00_5 = {5c 42 49 46 52 4f 53 54 5c 42 } //1 \BIFROST\B
		$a_01_6 = {4d 63 41 66 65 65 20 41 6e 74 69 76 69 72 75 73 } //1 McAfee Antivirus
		$a_00_7 = {61 76 67 63 63 33 32 2e 65 78 65 } //1 avgcc32.exe
		$a_00_8 = {50 65 73 74 50 61 74 72 6f 6c 2e 65 78 65 } //1 PestPatrol.exe
		$a_00_9 = {4e 76 63 63 2e 65 78 65 } //1 Nvcc.exe
		$a_00_10 = {49 6e 6f 52 70 63 2e 65 78 65 } //1 InoRpc.exe
		$a_00_11 = {25 64 20 6b 62 20 6f 66 } //1 %d kb of
		$a_00_12 = {44 6e 73 2f 49 50 20 31 } //1 Dns/IP 1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=7
 
}
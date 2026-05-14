
rule Trojan_Win64_Loader_P_MTB{
	meta:
		description = "Trojan:Win64/Loader.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5b 2d 5d 20 46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 70 61 79 6c 6f 61 64 20 44 4c 4c 20 61 74 20 70 61 74 68 3a } //1 [-] Failed to open payload DLL at path:
		$a_01_1 = {5b 2a 5d 20 53 74 65 70 20 31 3a 20 4f 70 65 6e 69 6e 67 20 73 61 63 72 69 66 69 63 69 61 6c 20 73 79 73 74 65 6d 20 44 4c 4c 20 28 77 69 6e 64 6f 77 73 2e 73 74 6f 72 61 67 65 2e 64 6c 6c 29 20 76 69 61 20 4e 74 4f 70 65 6e 46 69 6c 65 2e 2e 2e } //1 [*] Step 1: Opening sacrificial system DLL (windows.storage.dll) via NtOpenFile...
		$a_01_2 = {5b 2a 5d 20 53 74 65 70 20 32 3a 20 52 65 61 64 69 6e 67 20 70 61 79 6c 6f 61 64 20 44 4c 4c 20 66 72 6f 6d 20 64 69 73 6b 2e 2e 2e } //1 [*] Step 2: Reading payload DLL from disk...
		$a_01_3 = {5b 2a 5d 20 4d 6f 6e 69 74 6f 72 69 6e 67 20 70 61 79 6c 6f 61 64 20 65 78 65 63 75 74 69 6f 6e 20 73 74 61 74 75 73 2e 2e 2e } //1 [*] Monitoring payload execution status...
		$a_01_4 = {5b 2b 5d 20 49 6e 6a 65 63 74 69 6f 6e 20 73 65 71 75 65 6e 63 65 20 63 6f 6d 70 6c 65 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } //1 [+] Injection sequence completed successfully.
		$a_01_5 = {5b 2b 5d 20 43 6f 6e 74 61 63 74 3a 20 53 74 65 61 6c 74 68 20 4c 6f 61 64 65 72 20 73 74 61 72 74 65 64 2e } //1 [+] Contact: Stealth Loader started.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}

rule HackTool_Win32_DumpLsass_U_dha{
	meta:
		description = "HackTool:Win32/DumpLsass.U!dha,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {5b 2b 5d 20 53 74 61 72 74 69 6e 67 20 64 75 6d 70 20 74 6f 20 6d 65 6d 6f 72 79 20 62 75 66 66 65 72 } //1 [+] Starting dump to memory buffer
		$a_01_1 = {5b 2d 5d 20 43 6f 75 6c 64 20 6e 6f 74 20 67 65 74 20 63 75 72 72 65 6e 74 20 70 72 6f 63 65 73 73 20 74 6f 6b 65 6e 20 77 69 74 68 20 54 4f 4b 45 4e 5f 41 44 4a 55 53 54 5f 50 52 49 56 49 4c 45 47 45 53 } //1 [-] Could not get current process token with TOKEN_ADJUST_PRIVILEGES
		$a_01_2 = {5b 2d 5d 20 4e 6f 20 53 65 44 65 62 75 67 50 72 69 76 73 2e 20 4d 61 6b 65 20 73 75 72 65 20 79 6f 75 20 61 72 65 20 61 6e 20 61 64 6d 69 6e } //1 [-] No SeDebugPrivs. Make sure you are an admin
		$a_01_3 = {5b 2b 5d 20 53 65 61 72 63 68 69 6e 67 20 66 6f 72 20 4c 53 41 53 53 20 50 49 44 } //1 [+] Searching for LSASS PID
		$a_01_4 = {5b 2b 5d 20 4c 53 41 53 53 20 50 49 44 3a 20 25 69 } //1 [+] LSASS PID: %i
		$a_01_5 = {5b 2d 5d 20 43 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 20 68 61 6e 64 6c 65 20 74 6f 20 4c 53 41 53 53 20 70 72 6f 63 65 73 73 } //1 [-] Could not open handle to LSASS process
		$a_01_6 = {5b 2b 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 64 75 6d 70 65 64 20 4c 53 41 53 53 20 74 6f 20 6d 65 6d 6f 72 79 21 } //4 [+] Successfully dumped LSASS to memory!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*4) >=6
 
}
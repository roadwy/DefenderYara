
rule Backdoor_Win32_Gadwats_A{
	meta:
		description = "Backdoor:Win32/Gadwats.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {49 4e 53 54 41 4c 4c 5f 53 54 41 52 54 55 50 } //1 INSTALL_STARTUP
		$a_01_1 = {53 43 52 45 45 4e 53 48 4f 54 } //1 SCREENSHOT
		$a_01_2 = {52 55 4e 5f 4e 4f 53 48 45 4c 4c } //1 RUN_NOSHELL
		$a_01_3 = {52 55 4e 5f 41 53 59 4e 43 } //1 RUN_ASYNC
		$a_01_4 = {63 6d 64 5f 69 64 } //1 cmd_id
		$a_01_5 = {5b 57 5d 20 43 68 65 63 6b 69 6e 67 20 6d 75 74 65 78 2c 20 77 69 6c 6c 20 71 75 69 74 20 69 66 20 66 6f 75 6e 64 2e 2e 2e } //1 [W] Checking mutex, will quit if found...
		$a_01_6 = {5b 57 5d 20 56 65 72 69 66 79 69 6e 67 20 69 66 20 6d 75 74 65 78 20 69 73 20 70 72 65 73 65 6e 74 2e 2e 2e } //1 [W] Verifying if mutex is present...
		$a_01_7 = {5b 57 5d 20 53 74 61 72 74 69 6e 67 20 61 67 65 6e 74 2e 2e 2e } //1 [W] Starting agent...
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}

rule Trojan_Win32_Dexter_EC_MTB{
	meta:
		description = "Trojan:Win32/Dexter.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_81_0 = {4e 6f 77 20 61 6c 6c 20 74 68 65 20 65 76 61 73 69 6f 6e 20 74 65 63 68 6e 69 71 75 65 73 20 79 6f 75 20 64 65 63 69 64 65 64 20 77 69 6c 6c 20 62 65 20 75 73 65 64 } //01 00  Now all the evasion techniques you decided will be used
		$a_81_1 = {49 66 20 73 6f 6d 65 20 6f 66 20 74 68 65 6d 20 64 65 74 65 63 74 20 74 6f 20 62 65 20 75 6e 64 65 72 20 61 6e 61 6c 79 73 69 73 20 79 6f 75 72 20 70 72 6f 67 72 61 6d 20 77 69 6c 6c 20 62 65 20 6e 6f 20 6c 61 75 6e 63 68 65 64 2e } //01 00  If some of them detect to be under analysis your program will be no launched.
		$a_81_2 = {43 68 65 63 6b 69 6e 67 20 70 72 6f 63 65 73 73 20 6f 66 20 6d 61 6c 77 61 72 65 20 61 6e 61 6c 79 73 69 73 20 74 6f 6f 6c } //01 00  Checking process of malware analysis tool
		$a_81_3 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } //01 00  ollydbg.exe
		$a_81_4 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } //01 00  ProcessHacker.exe
		$a_81_5 = {74 63 70 76 69 65 77 2e 65 78 65 } //01 00  tcpview.exe
		$a_81_6 = {56 42 6f 78 4d 6f 75 73 65 2e 73 79 73 } //01 00  VBoxMouse.sys
		$a_81_7 = {56 42 6f 78 47 75 65 73 74 2e 73 79 73 } //01 00  VBoxGuest.sys
		$a_81_8 = {56 42 6f 78 53 46 2e 73 79 73 } //01 00  VBoxSF.sys
		$a_81_9 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 68 79 73 69 63 61 6c 4d 65 6d 6f 72 79 } //01 00  SELECT * FROM Win32_PhysicalMemory
		$a_81_10 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4d 65 6d 6f 72 79 44 65 76 69 63 65 } //01 00  SELECT * FROM Win32_MemoryDevice
		$a_81_11 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4d 65 6d 6f 72 79 41 72 72 61 79 } //00 00  SELECT * FROM Win32_MemoryArray
	condition:
		any of ($a_*)
 
}
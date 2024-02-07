
rule Trojan_Win32_Simda_gen_E{
	meta:
		description = "Trojan:Win32/Simda.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0c 00 00 02 00 "
		
	strings :
		$a_00_0 = {5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c } //02 00  \globalroot\systemroot\system32\
		$a_00_1 = {41 76 49 70 63 43 6f 6e 6e 65 63 74 } //02 00  AvIpcConnect
		$a_00_2 = {5f 5f 5f 5f 41 56 50 2e 52 6f 6f 74 } //02 00  ____AVP.Root
		$a_00_3 = {61 76 67 75 61 72 64 30 31 } //02 00  avguard01
		$a_00_4 = {64 72 69 76 65 72 73 5c 61 76 67 74 64 69 78 2e 73 79 73 } //02 00  drivers\avgtdix.sys
		$a_00_5 = {41 56 47 54 52 41 59 2e 45 58 45 } //02 00  AVGTRAY.EXE
		$a_00_6 = {5c 5c 2e 5c 4b 6d 78 41 67 65 6e 74 } //01 00  \\.\KmxAgent
		$a_00_7 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //01 00  CreateRemoteThread
		$a_00_8 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_00_9 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //01 00  OpenProcess
		$a_00_10 = {66 81 38 4d 5a 75 18 8b 48 3c 03 c8 81 39 50 45 00 00 75 0b 8b 49 50 51 50 ff 15 } //02 00 
		$a_02_11 = {71 77 65 72 90 02 04 71 77 65 72 74 90 02 04 71 77 65 72 74 79 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
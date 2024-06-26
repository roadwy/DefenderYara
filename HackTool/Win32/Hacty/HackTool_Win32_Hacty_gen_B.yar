
rule HackTool_Win32_Hacty_gen_B{
	meta:
		description = "HackTool:Win32/Hacty.gen!B,SIGNATURE_TYPE_PEHSTR,19 00 10 00 0d 00 00 02 00 "
		
	strings :
		$a_01_0 = {4d 5a 20 53 20 43 20 4f 20 52 20 45 50 45 } //03 00  MZ S C O R EPE
		$a_01_1 = {2a 2a 20 52 75 6e 6e 69 6e 67 20 6b 49 6e 6a 65 63 74 20 76 31 2e 30 20 62 79 20 4b 64 6d 20 28 6b 6f 64 6d 61 6b 65 72 40 6e 65 74 63 6f 75 72 72 69 65 72 2e 63 6f 6d 29 20 2a 2a } //03 00  ** Running kInject v1.0 by Kdm (kodmaker@netcourrier.com) **
		$a_01_2 = {74 20 6f 70 65 6e 20 70 72 6f 63 65 73 73 2e 20 28 53 75 72 65 20 69 74 20 65 78 69 73 74 73 20 3f 29 } //02 00  t open process. (Sure it exists ?)
		$a_01_3 = {47 65 74 50 69 64 42 79 4e 61 6d 65 20 66 61 69 6c 65 64 } //02 00  GetPidByName failed
		$a_01_4 = {4f 70 65 6e 50 72 6f 63 65 73 73 20 66 61 69 6c 65 64 2c 20 74 72 69 67 67 65 72 69 6e 67 20 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //03 00  OpenProcess failed, triggering DebugPrivilege
		$a_01_5 = {5b 21 5d 20 45 72 72 6f 72 20 77 68 69 6c 65 20 67 65 74 74 69 6e 67 20 4c 6f 61 64 4c 69 62 72 61 72 79 41 20 61 64 64 72 65 73 73 } //02 00  [!] Error while getting LoadLibraryA address
		$a_01_6 = {5b 21 5d 20 43 61 6e 6e 6f 74 20 63 72 65 61 74 65 20 74 68 72 65 61 64 } //02 00  [!] Cannot create thread
		$a_01_7 = {5b 21 5d 20 54 68 72 65 61 64 20 54 49 4d 45 20 4f 55 54 } //03 00  [!] Thread TIME OUT
		$a_01_8 = {65 63 74 2e 65 78 65 20 5b 70 72 6f 63 65 73 73 20 70 61 74 68 2f 50 69 64 5d 20 5b 64 6c 6c 20 70 61 74 68 5d 20 5b 2d 2d 63 72 65 61 74 65 20 2f 20 2d 2d 72 75 6e 74 69 6d 65 5d 20 5b 2d 2d 72 65 73 6f 6c 76 65 5d 20 5b 2d 2d 66 6f 72 63 65 5d } //02 00  ect.exe [process path/Pid] [dll path] [--create / --runtime] [--resolve] [--force]
		$a_01_9 = {2d 2d 63 72 65 61 74 65 20 20 20 20 20 3a 20 70 72 6f 67 72 61 6d 20 77 69 6c 6c 20 63 72 65 61 74 65 20 74 68 65 20 70 72 6f 63 65 73 73 20 62 65 66 6f 72 65 20 69 6e 6a 65 63 74 69 6e 67 } //02 00  --create     : program will create the process before injecting
		$a_01_10 = {2d 2d 72 75 6e 74 69 6d 65 20 20 20 20 3a 20 69 6e 6a 65 63 74 20 61 6c 72 65 61 64 79 20 65 78 69 73 74 69 6e 67 20 70 72 6f 63 65 73 73 } //02 00  --runtime    : inject already existing process
		$a_01_11 = {2d 2d 72 65 73 6f 6c 76 65 20 20 20 20 3a 20 67 65 74 20 70 72 6f 63 65 73 73 20 69 64 20 66 72 6f 6d 20 65 78 65 63 75 74 61 62 6c 65 20 6e 61 6d 65 } //02 00  --resolve    : get process id from executable name
		$a_01_12 = {2d 2d 66 6f 72 63 65 20 20 20 20 20 20 3a 20 6c 6f 61 64 20 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 20 74 6f 20 62 72 65 61 6b 20 69 6e 74 6f 20 74 61 72 67 65 74 20 70 72 6f 63 65 73 73 } //00 00  --force      : load SeDebugPrivilege to break into target process
	condition:
		any of ($a_*)
 
}
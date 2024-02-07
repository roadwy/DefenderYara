
rule HackTool_Win32_Scanly_A_dha{
	meta:
		description = "HackTool:Win32/Scanly.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {55 73 61 67 65 3a 20 25 73 20 5b 2d 73 20 73 74 61 72 74 69 70 5d 20 5b 2d 65 20 65 6e 64 69 70 5d 20 5b 2d 70 20 70 6f 72 74 5d 20 5b 2d 74 20 74 69 6d 65 6f 75 74 5d 20 5b 2d 6e 20 6d 61 78 74 68 72 65 61 64 6e 75 6d 5d 20 5b 2d 6c 20 6c 6f 67 66 69 6c 65 5d } //02 00  Usage: %s [-s startip] [-e endip] [-p port] [-t timeout] [-n maxthreadnum] [-l logfile]
		$a_01_1 = {25 2d 34 30 73 20 56 65 6e 64 6f 72 5b 25 73 5d 56 65 72 73 69 6f 6e 5b 25 75 5d 48 6f 73 74 4e 61 6d 65 5b 25 73 5d } //02 00  %-40s Vendor[%s]Version[%u]HostName[%s]
		$a_01_2 = {5c 6d 79 73 63 61 6e 5f 76 65 72 2e 70 64 62 } //01 00  \myscan_ver.pdb
		$a_01_3 = {64 65 62 75 67 20 6d 73 73 71 6c 20 63 68 65 63 6b 20 31 } //01 00  debug mssql check 1
		$a_01_4 = {5b 46 6f 75 6e 64 3a 5d 20 25 73 20 50 6f 72 74 3a 20 25 64 20 6f 70 65 6e 2e } //00 00  [Found:] %s Port: %d open.
	condition:
		any of ($a_*)
 
}
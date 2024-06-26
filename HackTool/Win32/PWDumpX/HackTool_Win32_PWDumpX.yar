
rule HackTool_Win32_PWDumpX{
	meta:
		description = "HackTool:Win32/PWDumpX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 57 44 75 6d 70 58 } //01 00  PWDumpX
		$a_01_1 = {5b 2b 5d 20 55 73 65 72 6e 61 6d 65 3a 20 20 20 20 20 22 25 73 22 } //01 00  [+] Username:     "%s"
		$a_01_2 = {5b 2b 5d 20 23 20 6f 66 20 54 68 72 65 61 64 73 3a 20 22 36 34 22 } //01 00  [+] # of Threads: "64"
		$a_01_3 = {2f 2f 72 65 65 64 61 72 76 69 6e 2e 74 68 65 61 72 76 69 6e 73 2e 63 6f 6d 2f } //01 00  //reedarvin.thearvins.com/
		$a_01_4 = {25 73 5c 41 44 4d 49 4e 24 5c 73 79 73 74 65 6d 33 32 5c 44 75 6d 70 } //01 00  %s\ADMIN$\system32\Dump
		$a_01_5 = {50 57 43 61 63 68 65 2e 74 78 74 } //01 00  PWCache.txt
		$a_01_6 = {4c 53 41 53 65 63 72 65 74 73 2e 74 78 74 } //01 00  LSASecrets.txt
		$a_01_7 = {50 57 48 69 73 74 6f 72 79 48 61 73 68 65 73 2e 74 78 74 } //01 00  PWHistoryHashes.txt
		$a_01_8 = {50 57 48 61 73 68 65 73 2e 74 78 74 } //00 00  PWHashes.txt
	condition:
		any of ($a_*)
 
}
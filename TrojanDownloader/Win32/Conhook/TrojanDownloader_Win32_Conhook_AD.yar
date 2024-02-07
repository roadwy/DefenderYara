
rule TrojanDownloader_Win32_Conhook_AD{
	meta:
		description = "TrojanDownloader:Win32/Conhook.AD,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 72 69 6f 50 65 72 73 6f 6e 61 6c 46 69 72 65 77 61 6c 6c 53 65 72 76 65 72 } //01 00  KerioPersonalFirewallServer
		$a_01_1 = {6f 75 74 70 6f 73 74 2e 65 78 65 } //01 00  outpost.exe
		$a_01_2 = {7a 6c 63 6c 69 65 6e 74 2e 65 78 65 } //01 00  zlclient.exe
		$a_01_3 = {73 6d 63 2e 65 78 65 } //01 00  smc.exe
		$a_01_4 = {66 77 73 72 76 2e 65 78 65 } //01 00  fwsrv.exe
		$a_01_5 = {44 75 6e 63 61 6e 4d 75 74 65 78 } //01 00  DuncanMutex
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 49 6e 66 } //01 00  Software\Microsoft\DInf
		$a_01_7 = {7b 46 37 45 45 33 44 46 38 2d 41 39 44 30 2d 34 37 66 32 2d 39 34 39 34 2d 34 44 44 45 30 42 32 46 30 34 37 35 7d } //01 00  {F7EE3DF8-A9D0-47f2-9494-4DDE0B2F0475}
		$a_01_8 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  \shell\open\command
		$a_01_9 = {38 33 2e 31 34 39 2e 37 35 2e 35 34 2f 63 67 69 2d 62 69 6e } //00 00  83.149.75.54/cgi-bin
	condition:
		any of ($a_*)
 
}
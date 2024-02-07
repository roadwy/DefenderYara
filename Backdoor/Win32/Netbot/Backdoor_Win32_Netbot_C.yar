
rule Backdoor_Win32_Netbot_C{
	meta:
		description = "Backdoor:Win32/Netbot.C,SIGNATURE_TYPE_PEHSTR,1c 00 1c 00 12 00 00 14 00 "
		
	strings :
		$a_01_0 = {4c 39 49 57 32 51 42 32 33 2d 43 44 2d 45 44 46 2d 32 2d 32 32 64 32 2d 39 43 42 44 2d 30 30 57 53 46 53 38 41 52 36 2d 39 51 45 52 32 31 51 41 4a 50 4d } //01 00  L9IW2QB23-CD-EDF-2-22d2-9CBD-00WSFS8AR6-9QER21QAJPM
		$a_01_1 = {5c 6d 73 63 69 64 61 65 6d 6f 6e 2e 63 6f 6d } //01 00  \mscidaemon.com
		$a_01_2 = {5c 6d 73 63 69 64 61 65 6d 6f 6e 2e 65 78 65 } //01 00  \mscidaemon.exe
		$a_01_3 = {5c 6d 73 63 69 64 61 65 6d 6f 6e 2e 64 6c 6c } //01 00  \mscidaemon.dll
		$a_01_4 = {50 4f 50 33 20 50 61 73 73 77 6f 72 64 32 } //01 00  POP3 Password2
		$a_01_5 = {50 4f 50 33 20 53 65 72 76 65 72 } //01 00  POP3 Server
		$a_01_6 = {50 4f 50 33 20 55 73 65 72 20 4e 61 6d 65 } //01 00  POP3 User Name
		$a_01_7 = {48 54 54 50 4d 61 69 6c 20 50 61 73 73 77 6f 72 64 32 } //01 00  HTTPMail Password2
		$a_01_8 = {48 6f 74 6d 61 69 6c } //01 00  Hotmail
		$a_01_9 = {48 54 54 50 4d 61 69 6c 20 55 73 65 72 20 4e 61 6d 65 } //01 00  HTTPMail User Name
		$a_01_10 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //01 00  Software\Microsoft\Internet Account Manager\Accounts
		$a_01_11 = {52 65 73 20 4e 61 6d 65 3a 25 73 20 52 65 73 20 54 79 70 65 3a 25 73 20 55 73 65 72 3a 25 73 20 50 61 73 73 20 3a 25 73 } //01 00  Res Name:%s Res Type:%s User:%s Pass :%s
		$a_01_12 = {55 3a 25 73 20 50 20 3a 25 73 } //01 00  U:%s P :%s
		$a_01_13 = {41 75 74 6f 43 6f 6d 70 20 50 61 73 } //01 00  AutoComp Pas
		$a_01_14 = {4d 53 4e 20 45 78 70 6c 6f 72 65 72 20 53 69 67 6e 75 70 } //01 00  MSN Explorer Signup
		$a_01_15 = {4f 75 74 45 78 70 } //01 00  OutExp
		$a_01_16 = {49 45 3a 50 61 73 2d 50 72 6f 74 20 73 69 74 65 73 } //01 00  IE:Pas-Prot sites
		$a_01_17 = {45 58 50 4c 4f 52 45 52 2e 45 58 45 } //00 00  EXPLORER.EXE
	condition:
		any of ($a_*)
 
}

rule Backdoor_Win32_Rbot_gen_A{
	meta:
		description = "Backdoor:Win32/Rbot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,31 01 2c 01 21 00 00 32 00 "
		
	strings :
		$a_00_0 = {6e 65 74 20 73 68 61 72 65 20 61 64 6d 69 6e 24 20 2f 64 65 6c 65 74 65 20 2f 79 } //32 00  net share admin$ /delete /y
		$a_00_1 = {6e 65 74 20 73 68 61 72 65 20 69 70 63 24 20 2f 64 65 6c 65 74 65 20 2f 79 } //32 00  net share ipc$ /delete /y
		$a_00_2 = {6e 65 74 20 73 68 61 72 65 20 64 24 20 2f 64 65 6c 65 74 65 20 2f 79 } //32 00  net share d$ /delete /y
		$a_00_3 = {6e 65 74 20 73 68 61 72 65 20 63 24 20 2f 64 65 6c 65 74 65 20 2f 79 } //0a 00  net share c$ /delete /y
		$a_00_4 = {6e 69 63 6b 73 65 72 76 20 69 64 6e 65 74 69 66 79 } //0a 00  nickserv idnetify
		$a_00_5 = {61 75 74 68 73 65 72 76 20 61 75 74 68 } //0a 00  authserv auth
		$a_00_6 = {73 6e 69 66 66 } //0a 00  sniff
		$a_00_7 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //0a 00  explorer.exe
		$a_00_8 = {4c 6d 48 6f 73 74 73 } //0a 00  LmHosts
		$a_00_9 = {4a 4f 49 4e } //0a 00  JOIN
		$a_00_10 = {4e 49 43 4b } //0a 00  NICK
		$a_00_11 = {50 52 49 56 4d 53 47 } //0a 00  PRIVMSG
		$a_00_12 = {73 74 61 72 74 20 2f 6d 69 6e 20 63 6d 64 2e 65 78 65 20 2f 63 } //01 00  start /min cmd.exe /c
		$a_00_13 = {37 32 2e 32 30 2e 32 31 2e 36 31 } //01 00  72.20.21.61
		$a_00_14 = {70 61 73 73 3d } //01 00  pass=
		$a_00_15 = {70 61 73 73 77 6f 72 64 3d } //01 00  password=
		$a_00_16 = {70 61 73 73 77 64 3d } //01 00  passwd=
		$a_00_17 = {70 61 79 70 61 6c } //01 00  paypal
		$a_00_18 = {50 72 6f 74 65 63 74 65 64 53 74 6f 72 61 67 65 } //01 00  ProtectedStorage
		$a_00_19 = {50 6f 6c 69 63 79 41 67 65 6e 74 } //01 00  PolicyAgent
		$a_00_20 = {4d 65 73 73 65 6e 67 65 72 } //01 00  Messenger
		$a_00_21 = {43 72 79 70 74 53 76 63 } //01 00  CryptSvc
		$a_00_22 = {46 6f 75 6e 64 20 57 69 6e 64 6f 77 73 20 50 72 6f 64 75 63 74 20 49 44 } //01 00  Found Windows Product ID
		$a_00_23 = {79 61 68 6f 6f 2e 63 6f 2e 6a 70 } //01 00  yahoo.co.jp
		$a_00_24 = {77 77 77 2e 6e 69 66 74 79 2e 63 6f 6d } //01 00  www.nifty.com
		$a_00_25 = {77 77 77 2e 61 62 6f 76 65 2e 6e 65 74 } //01 00  www.above.net
		$a_00_26 = {77 77 77 2e 6c 65 76 65 6c 33 2e 63 6f 6d } //01 00  www.level3.com
		$a_00_27 = {77 77 77 2e 73 74 61 6e 66 6f 72 64 2e 65 64 75 } //01 00  www.stanford.edu
		$a_00_28 = {49 63 6d 70 43 72 65 61 74 65 46 69 6c 65 } //01 00  IcmpCreateFile
		$a_01_29 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_00_30 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 } //01 00  RegisterServiceProcess
		$a_01_31 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_00_32 = {59 61 68 6f 6f 21 20 55 73 65 72 20 49 44 } //00 00  Yahoo! User ID
	condition:
		any of ($a_*)
 
}
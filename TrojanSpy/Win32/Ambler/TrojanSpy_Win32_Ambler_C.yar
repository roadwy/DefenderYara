
rule TrojanSpy_Win32_Ambler_C{
	meta:
		description = "TrojanSpy:Win32/Ambler.C,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 25 00 00 0f 00 "
		
	strings :
		$a_02_0 = {59 6a 01 59 3b c1 7e 0e 0f be b1 90 01 04 33 d6 41 3b c8 7c f2 3b 15 90 01 04 74 07 33 c0 e9 90 01 02 00 00 90 00 } //02 00 
		$a_01_1 = {4f 56 45 52 53 3d 25 73 } //02 00  OVERS=%s
		$a_01_2 = {43 4c 49 43 4b 53 3d 25 73 } //02 00  CLICKS=%s
		$a_01_3 = {4b 45 59 53 52 45 41 44 3a 25 73 } //02 00  KEYSREAD:%s
		$a_01_4 = {4b 45 59 4c 4f 47 47 45 44 3a 25 73 20 4b 45 59 53 52 45 41 44 3a 25 73 } //01 00  KEYLOGGED:%s KEYSREAD:%s
		$a_01_5 = {5c 70 73 2e 64 61 74 } //01 00  \ps.dat
		$a_01_6 = {5c 61 6c 6f 67 2e 74 78 74 } //01 00  \alog.txt
		$a_01_7 = {5c 61 63 63 73 2e 74 78 74 } //01 00  \accs.txt
		$a_01_8 = {5c 62 6f 61 2e 64 61 74 } //01 00  \boa.dat
		$a_01_9 = {6e 65 74 68 65 6c 70 65 72 } //01 00  nethelper
		$a_01_10 = {48 65 6c 70 65 72 4d 75 74 65 78 } //01 00  HelperMutex
		$a_01_11 = {73 75 62 6a 65 63 74 3d 4e 4f 4e 45 26 63 6f 6e 74 65 6e 74 3d } //01 00  subject=NONE&content=
		$a_01_12 = {73 75 62 6a 65 63 74 3d 25 73 26 63 6f 6e 74 65 6e 74 3d } //01 00  subject=%s&content=
		$a_01_13 = {5c 63 6f 6d 6d 61 6e 64 73 2e 78 6d 6c } //01 00  \commands.xml
		$a_01_14 = {5c 63 6f 6d 6d 61 6e 64 68 65 6c 70 65 72 2e 78 6d 6c } //01 00  \commandhelper.xml
		$a_01_15 = {5c 6e 65 74 68 65 6c 70 65 72 2e 78 6d 6c } //01 00  \nethelper.xml
		$a_01_16 = {5c 6e 65 74 68 65 6c 70 65 72 32 2e 78 6d 6c } //01 00  \nethelper2.xml
		$a_01_17 = {5c 68 65 6c 70 65 72 2e 78 6d 6c } //01 00  \helper.xml
		$a_01_18 = {5c 68 65 6c 70 65 72 32 2e 78 6d 6c } //01 00  \helper2.xml
		$a_01_19 = {5c 68 65 6c 70 65 72 2e 64 6c 6c } //01 00  \helper.dll
		$a_01_20 = {5c 6e 65 74 68 65 6c 70 65 72 2e 64 6c 6c } //01 00  \nethelper.dll
		$a_01_21 = {5c 6e 65 74 68 65 6c 70 65 72 32 2e 64 6c 6c } //01 00  \nethelper2.dll
		$a_01_22 = {4b 49 4c 4c 57 49 4e 41 4e 44 52 45 42 4f 4f 54 } //01 00  KILLWINANDREBOOT
		$a_01_23 = {4b 49 4c 4c 57 49 4e } //01 00  KILLWIN
		$a_01_24 = {55 4e 42 4c 4f 43 4b 53 49 54 45 } //01 00  UNBLOCKSITE
		$a_01_25 = {42 4c 4f 43 4b 53 49 54 45 } //01 00  BLOCKSITE
		$a_01_26 = {44 45 4c 45 54 45 42 4f 46 41 4b 45 59 53 } //01 00  DELETEBOFAKEYS
		$a_01_27 = {43 4f 50 59 42 4f 46 41 4b 45 59 53 } //01 00  COPYBOFAKEYS
		$a_01_28 = {44 4f 57 4e 4c 4f 41 44 } //01 00  DOWNLOAD
		$a_01_29 = {4c 4f 41 44 58 4d 4c } //01 00  LOADXML
		$a_01_30 = {44 45 4c 45 54 45 53 45 4c 46 } //01 00  DELETESELF
		$a_01_31 = {44 45 4c 45 54 45 43 4f 4f 4b 49 45 53 } //01 00  DELETECOOKIES
		$a_01_32 = {48 4f 53 54 41 44 44 } //01 00  HOSTADD
		$a_01_33 = {6d 61 69 6c 73 63 72 69 70 74 } //01 00  mailscript
		$a_01_34 = {6e 65 77 75 73 65 72 73 63 72 69 70 74 } //01 00  newuserscript
		$a_01_35 = {61 63 6b 63 6f 6d 6d 61 6e 64 73 63 72 69 70 74 } //01 00  ackcommandscript
		$a_01_36 = {63 6f 6d 6d 61 6e 64 73 63 72 69 70 74 } //00 00  commandscript
	condition:
		any of ($a_*)
 
}
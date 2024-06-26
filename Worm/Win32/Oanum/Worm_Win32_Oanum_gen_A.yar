
rule Worm_Win32_Oanum_gen_A{
	meta:
		description = "Worm:Win32/Oanum.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 12 00 19 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 83 c0 04 c1 ea 02 3b ca } //02 00 
		$a_02_1 = {51 51 56 57 68 00 00 04 00 e8 90 01 02 ff ff 8b f0 33 ff 3b f7 59 75 04 33 c0 90 00 } //03 00 
		$a_00_2 = {74 d2 46 46 b8 00 05 00 00 3b 45 08 1b c0 f7 d8 03 f0 39 7d 08 } //03 00 
		$a_00_3 = {8a 14 08 03 c1 88 14 0f 47 40 8a 10 88 14 0f 47 40 4e 75 f6 } //01 00 
		$a_00_4 = {57 49 4e 44 4f 57 53 5c 73 76 63 68 30 73 74 2e 65 78 65 } //01 00  WINDOWS\svch0st.exe
		$a_00_5 = {43 3a 5c 50 72 6f 67 72 61 7e 31 5c 45 73 65 74 } //01 00  C:\Progra~1\Eset
		$a_00_6 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  \Windows\CurrentVersion\Run
		$a_00_7 = {44 4f 57 4e 4b 49 4c 4c 4c 49 53 54 } //01 00  DOWNKILLLIST
		$a_00_8 = {44 4f 57 4e 4c 4f 41 44 4e 55 4d 53 } //01 00  DOWNLOADNUMS
		$a_00_9 = {6b 69 6c 6c 70 72 6f 63 } //01 00  killproc
		$a_00_10 = {43 68 6b 53 75 6d } //01 00  ChkSum
		$a_00_11 = {66 65 72 65 66 69 6c 65 } //01 00  ferefile
		$a_00_12 = {52 45 4d 4f 56 52 45 47 4c 49 53 54 } //01 00  REMOVREGLIST
		$a_00_13 = {72 65 6d 6f 76 72 65 67 } //01 00  removreg
		$a_00_14 = {44 4f 57 4e 46 49 4c 45 4c 49 53 54 } //01 00  DOWNFILELIST
		$a_00_15 = {64 6f 77 6e 66 69 6c 65 } //01 00  downfile
		$a_00_16 = {44 4f 57 4e 4d 41 49 4e 4c 49 53 54 } //01 00  DOWNMAINLIST
		$a_00_17 = {6d 61 69 6e 66 69 6c 65 } //01 00  mainfile
		$a_00_18 = {5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00  \explorer.exe
		$a_00_19 = {5f 66 65 72 65 5f } //01 00  _fere_
		$a_00_20 = {2f 63 6f 6e 66 69 67 2e } //01 00  /config.
		$a_00_21 = {72 61 76 74 61 73 6b } //01 00  ravtask
		$a_00_22 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //01 00  TerminateProcess
		$a_00_23 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //01 00  OpenProcess
		$a_01_24 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //00 00  CreateRemoteThread
	condition:
		any of ($a_*)
 
}
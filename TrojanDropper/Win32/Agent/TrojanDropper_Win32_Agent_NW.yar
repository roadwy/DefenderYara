
rule TrojanDropper_Win32_Agent_NW{
	meta:
		description = "TrojanDropper:Win32/Agent.NW,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 65 73 65 6e 74 70 72 66 2e 69 6e 69 } //01 00  \esentprf.ini
		$a_01_1 = {6c 69 73 74 3d 32 30 33 2c 32 30 35 2c 32 30 36 } //01 00  list=203,205,206
		$a_01_2 = {73 63 2e 65 78 65 20 73 74 6f 70 } //01 00  sc.exe stop
		$a_01_3 = {73 63 2e 65 78 65 20 63 72 65 61 74 65 } //01 00  sc.exe create
		$a_01_4 = {74 79 70 65 3d 20 6b 65 72 6e 65 6c 20 73 74 61 72 74 3d 20 61 75 74 6f 20 62 69 6e 70 61 74 68 3d } //01 00  type= kernel start= auto binpath=
		$a_01_5 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  http\shell\open\command
		$a_01_6 = {25 73 2e 6f 6c 64 } //01 00  %s.old
		$a_01_7 = {73 72 63 68 61 73 73 74 } //01 00  srchasst
		$a_01_8 = {6d 73 61 67 65 6e 74 } //01 00  msagent
		$a_01_9 = {25 73 5c 25 73 5c 25 73 25 73 } //01 00  %s\%s\%s%s
		$a_01_10 = {25 73 5c 64 6c 6c 63 61 63 68 65 5c 25 73 2e 73 79 73 } //01 00  %s\dllcache\%s.sys
		$a_01_11 = {25 73 5c 64 72 69 76 65 72 73 5c 25 73 2e 73 79 73 } //01 00  %s\drivers\%s.sys
		$a_01_12 = {69 70 66 6c 74 64 72 76 2e 73 79 73 } //01 00  ipfltdrv.sys
		$a_01_13 = {69 70 66 69 6c 74 65 72 64 72 69 76 65 72 } //01 00  ipfilterdriver
		$a_01_14 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 2e 65 78 65 20 31 32 37 2e 30 2e 30 2e 31 20 20 26 20 64 65 6c 20 20 22 } //00 00  cmd.exe /C ping.exe 127.0.0.1  & del  "
	condition:
		any of ($a_*)
 
}
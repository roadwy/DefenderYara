
rule Backdoor_Win32_Kluch_A{
	meta:
		description = "Backdoor:Win32/Kluch.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {57 4c 45 76 65 6e 74 53 74 61 72 74 53 68 65 6c 6c } //1 WLEventStartShell
		$a_01_1 = {6c 6f 67 6f 6e 20 69 73 20 53 74 61 72 74 53 68 65 6c 6c 54 68 72 65 61 64 21 21 21 } //1 logon is StartShellThread!!!
		$a_01_2 = {47 55 49 44 3d 32 66 34 62 33 37 35 62 39 6f 64 71 65 6a 6c 35 66 75 7a 61 34 35 26 4c 56 3d 32 30 30 37 37 26 56 3d 25 78 26 48 41 53 48 3d } //1 GUID=2f4b375b9odqejl5fuza45&LV=20077&V=%x&HASH=
		$a_01_3 = {47 6c 6f 62 61 6c 5c 46 32 42 41 46 32 36 38 45 45 46 46 44 44 00 } //1 汇扯污䙜䈲䙁㘲䔸䙅䑆D
		$a_01_4 = {44 65 63 74 43 6d 64 52 75 6e 2e 2e 2e 2e 3d 25 64 } //1 DectCmdRun....=%d
		$a_01_5 = {c6 45 fa 7c c6 45 fb bf c6 45 fc 4f c6 45 fd 7a c6 45 fe 6e c6 45 ff 8f f6 c3 07 74 03 43 eb f8 8d 7b 04 57 } //2
		$a_01_6 = {6e 53 74 61 72 74 54 79 70 65 3d 25 64 2c 73 7a 42 6b 44 6c 6c 49 6e 73 74 61 6c 6c 3d 25 73 } //1 nStartType=%d,szBkDllInstall=%s
		$a_01_7 = {30 30 34 35 33 32 32 63 66 61 2e 74 6d 70 } //1 0045322cfa.tmp
		$a_01_8 = {70 49 6e 66 6f 2d 6c 70 73 7a 50 72 6f 78 79 31 3d 25 73 } //1 pInfo-lpszProxy1=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}
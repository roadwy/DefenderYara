
rule Worm_Win32_Autorun_ABP{
	meta:
		description = "Worm:Win32/Autorun.ABP,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 77 69 6e 64 6f 77 73 78 70 2e 65 78 65 } //1 C:\WINDOWS\windowsxp.exe
		$a_01_1 = {22 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 5c 63 73 72 73 73 2e 65 78 65 22 20 2f 70 61 72 61 } //1 "C:\WINDOWS\system\csrss.exe" /para
		$a_01_2 = {43 3a 5c 52 45 43 59 43 4c 45 52 5c 53 2d 31 2d 35 2d 32 31 2d 31 34 38 32 34 37 36 35 30 31 2d 31 36 34 34 34 39 31 39 33 37 2d 36 38 32 30 30 33 33 33 30 2d 31 30 31 33 5c 73 6d 61 72 74 6d 67 72 2e 65 78 65 } //1 C:\RECYCLER\S-1-5-21-1482476501-1644491937-682003330-1013\smartmgr.exe
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c 7b 32 38 41 42 43 35 43 30 2d 34 46 43 42 2d 31 31 43 46 2d 41 41 58 35 2d 38 31 43 58 31 43 36 33 35 36 31 32 7d } //1 SOFTWARE\Microsoft\Active Setup\Installed Components\{28ABC5C0-4FCB-11CF-AAX5-81CX1C635612}
		$a_01_4 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_01_5 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 77 69 6e 64 6f 77 73 78 70 2e 65 78 65 } //1 shell\explore\Command=windowsxp.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}

rule Worm_Win32_Autorun_WL{
	meta:
		description = "Worm:Win32/Autorun.WL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 6e 77 6c 6e 25 5b 61 75 74 6f 72 75 6e 5d 60 6e 6f 70 65 6e 3d 43 4f 4e 54 52 4f 4c 5c 41 75 74 6f 52 75 6e 2e 65 78 65 20 a0 60 6e 73 68 65 6c 6c 5c 4f 70 65 6e 3d 26 4f 70 65 6e 60 6e 73 68 65 6c 6c 5c 4f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 43 4f 4e 54 52 4f 4c 5c 41 75 74 6f 52 75 6e 2e 65 78 65 20 a0 } //01 00 
		$a_01_1 = {49 6e 69 57 72 69 74 65 2c 20 7b 37 30 30 37 61 63 63 37 2d 33 32 30 32 2d 31 31 64 31 2d 61 61 64 32 2d 30 30 38 30 35 66 63 31 32 37 30 65 7d 20 2c 20 25 61 5f 70 72 6f 67 72 61 6d 66 69 6c 65 73 25 5c 57 65 62 53 65 63 75 72 69 74 79 5c 44 65 73 6b 74 6f 70 2e 69 6e 69 2c 20 2e 53 68 65 6c 6c 43 6c 61 73 73 49 6e 66 6f 2c 20 43 4c 53 49 44 } //01 00  IniWrite, {7007acc7-3202-11d1-aad2-00805fc1270e} , %a_programfiles%\WebSecurity\Desktop.ini, .ShellClassInfo, CLSID
		$a_01_2 = {75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 2c 20 68 74 74 70 3a 2f 2f 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 77 69 6e 64 6f 77 73 2f 2c 20 77 69 6e 75 70 64 63 68 6b 25 72 6e 6e 25 2e 6c 6f 67 } //00 00  urldownloadtofile, http://microsoft.com/windows/, winupdchk%rnn%.log
	condition:
		any of ($a_*)
 
}
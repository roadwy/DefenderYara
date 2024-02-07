
rule PWS_Win32_OnLineGames_LO{
	meta:
		description = "PWS:Win32/OnLineGames.LO,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 67 61 6d 65 5c 34 47 61 6d 65 4d 61 6e 61 67 65 72 } //01 00  4game\4GameManager
		$a_03_1 = {5f 7a 61 70 75 73 6b 61 74 90 01 01 72 2e 65 78 65 90 00 } //01 00 
		$a_01_2 = {52 6f 6c 6c 5c 52 65 64 5c 63 73 72 73 73 2e 65 78 65 } //01 00  Roll\Red\csrss.exe
		$a_01_3 = {4d 61 63 72 6f 5c 52 65 64 5c 74 61 73 6b 6d 67 72 2e 65 78 65 } //01 00  Macro\Red\taskmgr.exe
		$a_01_4 = {5c 53 79 73 5c 4d 61 63 72 6f 6d 65 64 69 61 46 6c 61 73 68 2e 65 78 65 } //01 00  \Sys\MacromediaFlash.exe
		$a_03_5 = {34 47 61 6d 65 5a 61 70 90 01 01 73 6b 61 74 72 90 00 } //01 00 
		$a_01_6 = {5c 5f 64 61 74 61 5f 65 63 2e 74 6d 70 } //01 00  \_data_ec.tmp
		$a_01_7 = {44 6f 77 65 6c 6f 72 5c 54 65 65 6d 5c 4b 6f 5c } //01 00  Dowelor\Teem\Ko\
		$a_01_8 = {56 69 73 69 74 5c 4e 6f 6c 79 5c 34 30 33 34 5c } //00 00  Visit\Noly\4034\
	condition:
		any of ($a_*)
 
}
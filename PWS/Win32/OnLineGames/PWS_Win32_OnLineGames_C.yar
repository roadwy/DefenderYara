
rule PWS_Win32_OnLineGames_C{
	meta:
		description = "PWS:Win32/OnLineGames.C,SIGNATURE_TYPE_PEHSTR_EXT,20 00 1f 00 09 00 00 05 00 "
		
	strings :
		$a_01_0 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 62 65 65 70 2e 62 69 6e } //05 00  \system32\drivers\beep.bin
		$a_01_1 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //05 00  KeServiceDescriptorTable
		$a_01_2 = {77 31 2e 62 61 74 } //05 00  w1.bat
		$a_01_3 = {69 66 20 65 78 69 73 74 20 25 73 00 64 65 6c 20 25 73 20 } //05 00 
		$a_01_4 = {41 70 70 49 6e 69 74 5f 44 4c 4c 73 } //05 00  AppInit_DLLs
		$a_03_5 = {53 79 73 57 90 01 04 2e 64 6c 6c 00 90 00 } //01 00 
		$a_01_6 = {48 4d 5f 4d 45 53 53 57 4f 57 48 48 48 44 4c 4c } //01 00  HM_MESSWOWHHHDLL
		$a_01_7 = {48 4d 5f 4d 45 53 53 57 4d 47 4a 48 43 48 44 4c 4c } //01 00  HM_MESSWMGJHCHDLL
		$a_01_8 = {48 4d 5f 4d 45 53 53 57 } //00 00  HM_MESSW
	condition:
		any of ($a_*)
 
}
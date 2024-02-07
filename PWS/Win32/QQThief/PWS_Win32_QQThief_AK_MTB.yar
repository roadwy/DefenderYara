
rule PWS_Win32_QQThief_AK_MTB{
	meta:
		description = "PWS:Win32/QQThief.AK!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 74 75 70 5f 66 61 74 33 32 73 79 73 } //01 00  setup_fat32sys
		$a_01_1 = {25 73 5c 4d 53 53 45 54 55 50 2e 44 41 54 } //01 00  %s\MSSETUP.DAT
		$a_01_2 = {25 73 5c 57 49 4e 44 4e 53 41 50 49 2e 44 41 54 } //01 00  %s\WINDNSAPI.DAT
		$a_01_3 = {25 73 5c 4d 53 53 59 53 54 45 4d 2e 44 41 54 } //01 00  %s\MSSYSTEM.DAT
		$a_01_4 = {2f 63 20 6d 6f 76 65 20 22 25 73 22 20 22 25 73 22 20 3e 20 6e 75 6c } //00 00  /c move "%s" "%s" > nul
	condition:
		any of ($a_*)
 
}
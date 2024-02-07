
rule PWS_Win32_Pebox_A{
	meta:
		description = "PWS:Win32/Pebox.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 11 00 00 05 00 "
		
	strings :
		$a_01_0 = {73 75 73 65 72 3d 25 73 26 73 70 61 73 73 3d 25 73 26 73 65 72 69 61 6c 3d 25 73 26 73 65 72 4e 75 6d } //05 00  suser=%s&spass=%s&serial=%s&serNum
		$a_01_1 = {73 75 73 65 72 3d 25 73 26 73 70 61 73 73 3d 25 73 26 6c 65 76 65 6c 3d 25 64 26 73 6e 61 6d 65 3d 25 73 26 6d 6f 6e 65 79 } //01 00  suser=%s&spass=%s&level=%d&sname=%s&money
		$a_01_2 = {63 3a 5c 70 61 73 73 2e 6c 6f 67 } //01 00  c:\pass.log
		$a_01_3 = {26 55 73 65 72 74 74 69 6e 67 2e 69 6e 69 } //01 00  &Usertting.ini
		$a_01_4 = {55 73 65 72 53 65 74 74 69 6e 67 2e 69 6e 69 } //01 00  UserSetting.ini
		$a_01_5 = {4c 61 73 74 53 65 6c 65 63 74 4e 61 6d 65 } //01 00  LastSelectName
		$a_01_6 = {54 65 6e 51 51 41 63 63 6f 75 6e 74 2e 64 6c 6c } //01 00  TenQQAccount.dll
		$a_01_7 = {4b 49 43 4b } //01 00  KICK
		$a_01_8 = {44 49 53 50 4c 41 59 } //01 00  DISPLAY
		$a_01_9 = {48 61 74 61 6e 65 6d 2e 64 61 74 } //01 00  Hatanem.dat
		$a_01_10 = {63 3a 5c 72 65 63 76 2e 6c 6f 67 } //01 00  c:\recv.log
		$a_01_11 = {63 3a 5c 73 65 6e 64 2e 6c 6f 67 } //01 00  c:\send.log
		$a_01_12 = {51 71 41 63 63 6f 75 6e 74 2e 64 6c 6c } //01 00  QqAccount.dll
		$a_01_13 = {6d 61 6b 65 73 75 72 65 74 68 69 73 6d 79 6d 61 69 6c } //01 00  makesurethismymail
		$a_01_14 = {75 70 6c 6f 61 64 61 69 6d 67 66 69 6c 65 } //01 00  uploadaimgfile
		$a_01_15 = {73 61 66 65 63 6f 64 65 3a } //01 00  safecode:
		$a_01_16 = {64 61 74 61 5c 63 6f 6e 66 69 67 2e 69 6e 69 } //00 00  data\config.ini
	condition:
		any of ($a_*)
 
}
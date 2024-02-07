
rule Worm_Win32_Semail_A{
	meta:
		description = "Worm:Win32/Semail.A,SIGNATURE_TYPE_PEHSTR_EXT,11 00 0f 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 53 45 52 43 4d 44 } //01 00  USERCMD
		$a_01_1 = {3c 50 49 44 3e } //01 00  <PID>
		$a_01_2 = {3c 49 44 3e } //01 00  <ID>
		$a_01_3 = {3c 55 49 4e 3e } //02 00  <UIN>
		$a_01_4 = {3c 4c 41 53 54 43 4d 44 3e } //03 00  <LASTCMD>
		$a_00_5 = {67 65 74 5f 63 6f 6d 6d 61 6e 64 2e 70 68 70 3f 50 49 44 3d 3c 50 49 44 3e 26 49 44 3d 3c 49 44 3e 26 4c 41 53 54 43 4d 44 3d 3c 4c 41 53 54 43 4d 44 3e } //01 00  get_command.php?PID=<PID>&ID=<ID>&LASTCMD=<LASTCMD>
		$a_01_6 = {41 54 54 41 43 48 4d 45 4e 54 } //01 00  ATTACHMENT
		$a_00_7 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 45 78 74 65 6e 73 69 6f 6e 73 5c 7b } //01 00  \Internet Explorer\Extensions\{
		$a_00_8 = {69 66 20 65 78 69 73 74 20 25 31 20 64 65 6c 20 25 31 20 3e 20 6e 75 6c } //01 00  if exist %1 del %1 > nul
		$a_00_9 = {64 65 6c 20 25 30 20 3e 20 6e 75 6c } //01 00  del %0 > nul
		$a_00_10 = {52 61 73 47 65 74 43 6f 75 6e 74 72 79 49 6e 66 6f 41 } //01 00  RasGetCountryInfoA
		$a_00_11 = {2d 75 69 6e 20 00 } //02 00  甭湩 
		$a_00_12 = {60 e8 00 00 00 00 5d eb 26 } //01 00 
		$a_01_13 = {46 72 65 65 4f 66 43 68 61 72 67 65 } //00 00  FreeOfCharge
	condition:
		any of ($a_*)
 
}
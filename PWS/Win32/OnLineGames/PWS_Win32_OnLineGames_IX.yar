
rule PWS_Win32_OnLineGames_IX{
	meta:
		description = "PWS:Win32/OnLineGames.IX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 76 63 77 65 74 } //01 00  fvcwet
		$a_01_1 = {5c 74 6f 79 70 65 64 6c 65 2e 64 6c 6c } //01 00  \toypedle.dll
		$a_01_2 = {21 40 23 2a 28 5e 23 40 24 40 21 21 2a 40 } //01 00  !@#*(^#@$@!!*@
		$a_01_3 = {26 78 79 33 3d 00 26 78 79 32 3d 00 26 78 79 31 3d 00 26 50 4e 61 6d 65 3d } //00 00 
	condition:
		any of ($a_*)
 
}
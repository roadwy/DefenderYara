
rule PWS_Win32_OnLineGames_JN{
	meta:
		description = "PWS:Win32/OnLineGames.JN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 62 69 6e 33 32 5c 62 79 7a 79 68 2e 65 78 65 } //01 00  \bin32\byzyh.exe
		$a_00_1 = {5c 62 69 6e 33 32 5c 72 61 73 61 64 68 6c 70 2e 64 6c 6c } //01 00  \bin32\rasadhlp.dll
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 73 6e 64 61 5c 41 49 4f 4e 5c 50 61 74 68 } //01 00  SOFTWARE\snda\AION\Path
		$a_02_3 = {6a 00 6a 00 6a 00 68 04 00 00 80 6a 00 68 90 01 03 00 68 01 03 00 80 6a 00 68 04 00 00 00 68 03 00 00 00 bb 98 06 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
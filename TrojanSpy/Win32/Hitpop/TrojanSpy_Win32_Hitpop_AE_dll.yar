
rule TrojanSpy_Win32_Hitpop_AE_dll{
	meta:
		description = "TrojanSpy:Win32/Hitpop.AE!dll,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {74 3d 6a 00 6a 00 8d 55 90 01 01 8b 45 90 01 01 8b 04 c5 90 01 04 e8 90 01 04 8b 4d 90 01 01 8d 45 90 01 01 ba 90 01 04 e8 90 01 04 8b 45 90 01 01 e8 90 01 04 50 68 90 01 04 6a 00 6a 00 e8 90 01 04 ff 45 f8 83 7d f8 0b 75 90 01 01 33 c0 5a 59 59 64 89 10 68 90 01 04 8d 45 90 01 01 ba 90 01 01 00 00 00 90 00 } //05 00 
		$a_02_1 = {6e 20 53 74 61 72 74 75 70 90 02 70 2e 6c 6e 6b 90 00 } //01 00 
		$a_00_2 = {5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e } //01 00  \Explorer\run
		$a_00_3 = {4b 56 58 50 2e 6b 78 70 } //01 00  KVXP.kxp
		$a_00_4 = {52 55 4e 49 45 50 2e 45 58 45 } //01 00  RUNIEP.EXE
		$a_00_5 = {4b 52 65 67 45 78 2e 65 78 65 } //01 00  KRegEx.exe
		$a_00_6 = {33 36 30 74 72 61 79 2e 65 78 65 } //00 00  360tray.exe
	condition:
		any of ($a_*)
 
}
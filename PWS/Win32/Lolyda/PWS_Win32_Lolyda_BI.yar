
rule PWS_Win32_Lolyda_BI{
	meta:
		description = "PWS:Win32/Lolyda.BI,SIGNATURE_TYPE_PEHSTR_EXT,16 00 14 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 73 65 63 69 76 72 65 53 5c 74 65 53 6c 6f 72 74 6e 6f 43 74 6e 65 72 72 75 43 5c 4d 45 54 53 59 53 } //0a 00  \secivreS\teSlortnoCtnerruC\METSYS
		$a_01_1 = {46 75 63 6b 20 59 6f 75 20 42 79 20 51 51 3a 31 32 33 2a 2a 33 32 31 } //01 00  Fuck You By QQ:123**321
		$a_00_2 = {44 72 61 67 6f 6e 4e 65 73 74 2e 65 78 65 } //01 00  DragonNest.exe
		$a_00_3 = {74 77 32 2e 65 78 65 } //01 00  tw2.exe
		$a_00_4 = {77 6f 77 2e 65 78 65 } //01 00  wow.exe
		$a_00_5 = {51 51 68 78 67 61 6d 65 2e 65 78 65 } //01 00  QQhxgame.exe
		$a_00_6 = {78 79 33 2e 65 78 65 } //01 00  xy3.exe
		$a_00_7 = {78 79 32 2e 65 78 65 } //00 00  xy2.exe
	condition:
		any of ($a_*)
 
}
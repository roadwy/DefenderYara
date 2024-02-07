
rule Worm_Win32_Bancos_B{
	meta:
		description = "Worm:Win32/Bancos.B,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //04 00  Software\Borland\Delphi\Locales
		$a_03_1 = {8b 83 20 03 00 00 90 09 4b 00 b8 90 01 03 00 33 d2 e8 90 01 02 ff ff 8d 45 e8 b9 44 dd 48 00 8b 15 b4 50 49 00 e8 90 01 03 ff 8b 45 e8 e8 90 01 02 ff ff b8 38 dd 48 00 33 d2 e8 90 01 02 ff ff b8 50 dd 48 00 33 d2 e8 90 01 02 ff ff e8 90 01 03 ff 8b 10 ff 52 10 b2 01 90 00 } //01 00 
		$a_00_2 = {6d 73 6e 2e 64 61 74 } //01 00  msn.dat
		$a_00_3 = {74 63 65 66 6e 69 2e 64 61 74 } //02 00  tcefni.dat
		$a_00_4 = {54 45 6e 76 69 61 4d 53 4e 54 69 6d 65 72 } //01 00  TEnviaMSNTimer
		$a_02_5 = {44 53 43 30 90 01 03 2e 5a 49 50 90 00 } //01 00 
		$a_00_6 = {64 6f 63 75 6d 65 6e 74 2e 67 65 74 45 6c 65 6d 65 6e 74 42 79 49 64 28 22 53 65 6e 64 4d 65 73 73 61 67 65 22 29 2e 63 6c 69 63 6b 28 29 } //01 00  document.getElementById("SendMessage").click()
		$a_00_7 = {67 6f 73 74 65 69 20 6d 75 69 74 6f 20 64 65 73 73 61 20 66 6f 74 6f 2e 2e 2e } //00 00  gostei muito dessa foto...
	condition:
		any of ($a_*)
 
}
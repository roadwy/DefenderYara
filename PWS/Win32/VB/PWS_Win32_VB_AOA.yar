
rule PWS_Win32_VB_AOA{
	meta:
		description = "PWS:Win32/VB.AOA,SIGNATURE_TYPE_PEHSTR_EXT,21 00 20 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //0a 00  MSVBVM60.DLL
		$a_00_1 = {47 6f 6c 64 20 65 20 63 61 73 68 20 48 61 63 6b 20 2d 20 42 79 20 4c 30 47 34 4e } //0a 00  Gold e cash Hack - By L0G4N
		$a_00_2 = {43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 44 00 69 00 65 00 67 00 6f 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 67 00 6f 00 6c 00 64 00 20 00 68 00 61 00 63 00 6b 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  C:\Documents and Settings\Diego\Desktop\gold hack\Project1.vbp
		$a_00_3 = {41 64 69 63 69 6f 6e 61 72 20 34 33 30 20 47 50 20 51 75 61 6e 64 6f 20 70 6f 73 73 69 76 65 6c 2e 2e 2e } //01 00  Adicionar 430 GP Quando possivel...
		$a_00_4 = {4f 63 75 6c 74 61 72 20 4c 6f 67 69 6e 20 28 52 65 63 6f 6d 65 6e 64 61 64 6f 21 29 } //01 00  Ocultar Login (Recomendado!)
		$a_00_5 = {54 65 6e 74 61 72 20 4f 63 75 6c 74 61 72 2d 73 65 20 64 6f 20 48 61 63 6b 20 53 68 69 65 6c 64 } //01 00  Tentar Ocultar-se do Hack Shield
		$a_00_6 = {68 74 74 70 3a 2f 2f 77 67 64 74 65 61 6d 2e 6a 63 6f 6e 73 65 72 76 2e 6e 65 74 } //01 00  http://wgdteam.jconserv.net
		$a_00_7 = {4c 00 6f 00 67 00 69 00 6e 00 20 00 3d 00 } //00 00  Login =
	condition:
		any of ($a_*)
 
}

rule TrojanDropper_O97M_Donoff_VZ{
	meta:
		description = "TrojanDropper:O97M/Donoff.VZ,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {2e 72 65 67 77 72 69 74 65 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  .regwrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  CreateObject("Wscript.Shell")
		$a_00_2 = {4f 75 74 55 70 64 61 74 65 } //01 00  OutUpdate
		$a_00_3 = {2c 57 69 6e 43 72 65 64 } //01 00  ,WinCred
		$a_00_4 = {4d 6f 64 20 26 48 31 30 30 } //01 00  Mod &H100
		$a_00_5 = {2b 20 26 48 41 35 } //00 00  + &HA5
	condition:
		any of ($a_*)
 
}
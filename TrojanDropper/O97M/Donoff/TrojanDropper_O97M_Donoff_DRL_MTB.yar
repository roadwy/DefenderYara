
rule TrojanDropper_O97M_Donoff_DRL_MTB{
	meta:
		description = "TrojanDropper:O97M/Donoff.DRL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 5c 72 6f 6f 74 5c 63 69 6d 76 32 } //01 00  .\root\cimv2
		$a_01_1 = {77 69 6e 6d 67 6d 74 73 3a 72 6f 6f 74 5c 63 69 6d 76 32 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 } //01 00  winmgmts:root\cimv2:Win32_Process
		$a_01_2 = {22 70 6f 77 65 22 } //01 00  "powe"
		$a_01_3 = {78 20 2b 20 22 72 73 68 65 22 } //01 00  x + "rshe"
		$a_01_4 = {78 20 2b 20 22 6c 6c 20 2f 63 20 22 } //01 00  x + "ll /c "
		$a_01_5 = {61 70 70 44 61 74 61 20 2b 20 22 5c 63 61 6c 63 2e 65 78 65 22 } //01 00  appData + "\calc.exe"
		$a_01_6 = {79 2c 20 4e 75 6c 6c 2c 20 6f 62 6a 43 6f 6e 66 69 67 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 } //01 00  y, Null, objConfig, intProcessID
		$a_01_7 = {2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f } //01 00  .SpawnInstance_
		$a_01_8 = {65 72 72 52 65 74 75 72 6e } //00 00  errReturn
	condition:
		any of ($a_*)
 
}

rule TrojanDropper_O97M_Hancitor_HAP_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 30 72 64 2e 64 6c 6c } //01 00  W0rd.dll
		$a_01_1 = {26 20 6a 73 64 20 26 } //01 00  & jsd &
		$a_01_2 = {43 61 6c 6c 20 67 6f 74 6f 64 6f 77 6e } //01 00  Call gotodown
		$a_03_3 = {2e 74 6d 70 22 20 41 73 20 66 75 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_4 = {44 69 6d 20 72 65 67 73 72 76 61 20 41 73 20 4e 65 77 20 53 68 65 6c 6c 33 32 2e 53 68 65 6c 6c } //01 00  Dim regsrva As New Shell32.Shell
		$a_01_5 = {26 20 79 79 20 26 20 70 75 73 68 73 74 72 20 26 20 22 6c 6c 22 20 26 20 22 2c 22 20 26 20 22 55 6e 69 6e 73 74 61 6c 6c 46 6f 6e 74 } //01 00  & yy & pushstr & "ll" & "," & "UninstallFont
		$a_03_6 = {43 61 6c 6c 20 72 65 67 73 72 76 61 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 66 61 2c 20 79 79 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29 90 0c 02 00 45 6e 64 20 49 66 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
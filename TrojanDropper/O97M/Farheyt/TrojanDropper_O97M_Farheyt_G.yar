
rule TrojanDropper_O97M_Farheyt_G{
	meta:
		description = "TrojanDropper:O97M/Farheyt.G,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_02_0 = {3d 20 22 54 22 20 2b 20 90 05 20 06 61 2d 7a 30 2d 39 20 2b 20 22 50 22 90 00 } //02 00 
		$a_02_1 = {3d 20 45 6e 76 69 72 6f 6e 28 90 05 20 06 61 2d 7a 30 2d 39 29 20 2b 20 90 00 } //02 00 
		$a_02_2 = {2b 20 43 68 72 28 39 32 20 2b 20 31 30 20 2b 20 90 05 20 06 61 2d 7a 30 2d 39 29 20 26 20 22 78 22 90 00 } //01 00 
		$a_01_3 = {28 31 39 20 2b 20 36 38 29 20 26 20 22 6f 72 22 20 2b 20 22 64 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 } //01 00  (19 + 68) & "or" + "d.Application"
		$a_01_4 = {2b 20 43 68 72 28 39 20 2b 20 39 32 29 } //01 00  + Chr(9 + 92)
		$a_01_5 = {2b 20 22 72 22 20 26 20 22 74 66 22 } //02 00  + "r" & "tf"
		$a_01_6 = {2b 20 22 72 72 61 31 22 20 26 } //00 00  + "rra1" &
		$a_00_7 = {5d 04 00 00 } //f8 6e 
	condition:
		any of ($a_*)
 
}
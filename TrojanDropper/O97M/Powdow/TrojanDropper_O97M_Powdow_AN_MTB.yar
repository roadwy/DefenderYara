
rule TrojanDropper_O97M_Powdow_AN_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.AN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 49 66 20 56 42 41 37 20 54 68 65 6e } //01 00  #If VBA7 Then
		$a_01_1 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 47 65 74 4d 65 73 73 61 67 65 45 78 74 72 61 49 6e 66 6f 20 4c 69 62 20 22 75 73 65 72 33 32 22 20 28 29 20 41 73 20 4c 6f 6e 67 50 74 72 } //01 00  Public Declare PtrSafe Function GetMessageExtraInfo Lib "user32" () As LongPtr
		$a_01_2 = {53 68 65 6c 6c 57 61 69 74 20 3d 20 6c 45 78 69 74 43 6f 64 65 } //01 00  ShellWait = lExitCode
		$a_01_3 = {73 43 6f 6d 6d 61 6e 64 4c 69 6e 65 20 3d 20 22 22 22 22 20 26 20 73 46 69 6c 65 20 26 20 22 22 22 22 20 26 20 22 20 22 20 26 20 73 50 61 72 61 6d 73 } //01 00  sCommandLine = """" & sFile & """" & " " & sParams
		$a_03_4 = {50 72 69 6e 74 20 23 90 01 01 2c 20 43 53 74 72 28 90 02 15 2e 90 02 15 2e 43 61 70 74 69 6f 6e 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
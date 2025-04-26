
rule TrojanDropper_Linux_SideTwist_A{
	meta:
		description = "TrojanDropper:Linux/SideTwist.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {64 61 74 61 28 49 6e 64 65 78 29 20 3d 20 28 45 6e 63 44 61 74 61 30 20 2a 20 53 32 29 20 4f 72 20 28 45 6e 63 44 61 74 61 31 20 5c 20 53 34 29 } //data(Index) = (EncData0 * S2) Or (EncData1 \ S4)  1
		$a_80_1 = {74 61 72 67 65 74 53 75 62 66 6f 6c 64 65 72 20 3d 20 22 53 79 73 74 65 6d 22 20 26 20 22 46 61 69 6c 75 72 65 22 20 26 20 22 52 65 70 6f 72 74 65 72 22 } //targetSubfolder = "System" & "Failure" & "Reporter"  1
		$a_80_2 = {6d 61 69 6e 54 61 72 67 65 74 50 61 74 68 20 26 20 62 73 6c 61 73 68 20 26 20 74 61 72 67 65 74 53 75 62 66 6f 6c 64 65 72 20 26 20 62 73 6c 61 73 68 20 26 20 22 } //mainTargetPath & bslash & targetSubfolder & bslash & "  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}

rule TrojanDropper_O97M_Obfuse_PHF_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.PHF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 53 74 72 52 65 76 65 72 73 65 28 22 73 62 76 2e 6e 69 70 5c 61 74 61 44 6d 61 72 67 6f 72 50 5c 3a 43 20 65 78 65 2e 74 70 69 72 63 73 63 20 6b 2f 20 64 6d 63 22 29 2c 20 43 68 72 28 34 38 29 29 } //1 = Shell(StrReverse("sbv.nip\ataDmargorP\:C exe.tpircsc k/ dmc"), Chr(48))
		$a_01_1 = {49 6e 53 74 72 28 44 6f 6d 69 6e 69 6f 73 2c 20 73 53 70 6c 69 74 28 55 42 6f 75 6e 64 28 73 53 70 6c 69 74 29 29 29 20 3d 20 30 20 54 68 65 6e } //1 InStr(Dominios, sSplit(UBound(sSplit))) = 0 Then
		$a_01_2 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 49 5a 4f 49 5a 49 4d 49 5a 49 22 29 } //1 = StrReverse("IZOIZIMIZI")
		$a_01_3 = {3d 20 22 40 22 20 4f 72 20 4d 69 64 24 28 45 6d 61 69 6c 2c 20 4c 65 6e 28 45 6d 61 69 6c 29 2c 20 31 29 20 3d 20 22 40 22 20 4f 72 20 49 6e 53 74 72 28 45 6d 61 69 6c 2c 20 22 40 2e 22 29 } //1 = "@" Or Mid$(Email, Len(Email), 1) = "@" Or InStr(Email, "@.")
		$a_01_4 = {50 72 69 6e 74 20 23 4d 79 46 69 6c 65 2c 20 57 57 } //1 Print #MyFile, WW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
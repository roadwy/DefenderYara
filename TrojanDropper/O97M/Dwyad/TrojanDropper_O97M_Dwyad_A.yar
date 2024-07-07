
rule TrojanDropper_O97M_Dwyad_A{
	meta:
		description = "TrojanDropper:O97M/Dwyad.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 20 45 61 63 68 20 4f 70 74 69 70 6c 65 78 6f 70 74 69 63 6f 72 65 61 76 64 76 61 74 61 67 65 73 65 73 73 69 6f 6e 73 65 72 76 65 72 69 6e 67 6c 65 61 64 54 57 4f 4d 6f 6e 65 74 61 20 49 6e 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 72 61 67 72 61 70 68 73 } //1 For Each OptiplexopticoreavdvatagesessionserveringleadTWOMoneta In ActiveDocument.Paragraphs
		$a_01_1 = {57 68 69 6c 65 20 28 4f 70 74 69 70 6c 65 78 6f 70 74 69 63 6f 72 65 61 76 64 76 61 74 61 67 65 73 65 73 73 69 6f 6e 73 65 72 76 65 72 69 6e 67 6c 65 61 64 54 57 4f 42 69 7a 61 6e 63 6a 75 6d 20 3c 20 4c 65 6e 28 4f 70 74 69 70 6c 65 78 6f 70 74 69 63 6f 72 65 61 76 64 76 61 74 61 67 65 73 65 73 73 69 6f 6e 73 65 72 76 65 72 69 6e 67 6c 65 61 64 54 52 5a 59 45 78 74 61 31 29 29 } //1 While (OptiplexopticoreavdvatagesessionserveringleadTWOBizancjum < Len(OptiplexopticoreavdvatagesessionserveringleadTRZYExta1))
		$a_01_2 = {2b 20 22 48 22 20 26 20 4d 69 64 28 4f 70 74 69 70 6c 65 78 6f 70 74 69 63 6f 72 65 61 76 64 76 61 74 61 67 65 73 65 73 73 69 6f 6e 73 65 72 76 65 72 69 6e 67 6c 65 61 64 54 52 5a 59 45 78 74 61 31 2c 20 4f 70 74 69 70 6c 65 78 6f 70 74 69 63 6f 72 65 61 76 64 76 61 74 61 67 65 73 65 73 73 69 6f 6e 73 65 72 76 65 72 69 6e 67 6c 65 61 64 54 57 4f 42 69 7a 61 6e 63 6a 75 6d 2c 20 32 29 } //1 + "H" & Mid(OptiplexopticoreavdvatagesessionserveringleadTRZYExta1, OptiplexopticoreavdvatagesessionserveringleadTWOBizancjum, 2)
		$a_01_3 = {4f 70 74 69 70 6c 65 78 6f 70 74 69 63 6f 72 65 61 76 64 76 61 74 61 67 65 73 65 73 73 69 6f 6e 73 65 72 76 65 72 69 6e 67 6c 65 61 64 4f 4e 45 4b 6f 74 6c 65 74 61 20 3d 20 45 6e 76 69 72 6f 6e 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 20 2b 20 22 5c 4d 65 6d 53 79 73 22 20 2b 20 43 68 72 28 4c 52 61 6e 64 6f 6d 4e 75 6d 62 65 72 29 20 2b 20 43 68 72 28 4c 52 61 6e 64 6f 6d 4e 75 6d 62 65 72 32 29 } //1 OptiplexopticoreavdvatagesessionserveringleadONEKotleta = Environ("ALLUSERSPROFILE") + "\MemSys" + Chr(LRandomNumber) + Chr(LRandomNumber2)
		$a_01_4 = {44 69 66 64 6d 61 70 71 65 6d 6b 68 34 37 20 3d 20 53 68 65 6c 6c 28 58 6a 65 71 6a 70 65 77 6b 6a 71 33 32 2c 20 30 29 } //1 Difdmapqemkh47 = Shell(Xjeqjpewkjq32, 0)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}
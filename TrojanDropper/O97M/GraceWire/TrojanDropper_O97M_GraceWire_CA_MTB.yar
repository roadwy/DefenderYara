
rule TrojanDropper_O97M_GraceWire_CA_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 4f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 73 65 6e 64 69 6e 67 73 43 53 54 52 20 2b 20 22 2e 64 6c 6c 22 } //1 sOfbl = ofbl + sendingsCSTR + ".dll"
		$a_01_1 = {43 6f 6d 70 6f 73 69 74 69 6f 6e 20 64 65 72 73 68 6c 65 70 20 26 20 57 69 6e 64 6f 77 73 2e 4c 61 62 65 6c 31 2e 54 61 67 2c 20 73 4f 66 62 6c 2c 20 43 75 72 72 65 6e 74 53 69 7a 65 4f 66 41 54 2c 20 73 65 6e 64 69 6e 67 73 } //1 Composition dershlep & Windows.Label1.Tag, sOfbl, CurrentSizeOfAT, sendings
		$a_01_2 = {74 65 78 74 49 74 65 6d 20 3d 20 57 69 6e 64 6f 77 73 2e 4c 61 62 65 6c 31 31 2e 43 61 70 74 69 6f 6e } //1 textItem = Windows.Label11.Caption
		$a_01_3 = {53 65 74 20 44 65 73 74 69 6e 61 74 69 6f 6e 4b 61 74 20 3d 20 73 4e 4d 53 50 2e 4e 61 6d 65 73 70 61 63 65 28 64 65 72 73 68 6c 65 70 29 } //1 Set DestinationKat = sNMSP.Namespace(dershlep)
		$a_03_4 = {4b 69 6c 6c 20 4b 65 79 90 02 08 4e 65 78 74 20 4b 65 79 90 02 08 4f 6e 20 45 72 72 6f 72 20 47 6f 54 6f 20 30 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
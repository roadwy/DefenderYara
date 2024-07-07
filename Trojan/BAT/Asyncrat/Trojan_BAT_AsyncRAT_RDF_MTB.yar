
rule Trojan_BAT_AsyncRAT_RDF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 4d 53 4c 6f 63 61 6c 53 65 72 76 65 72 } //1 KMSLocalServer
		$a_01_1 = {64 50 71 4c 43 4f 42 55 78 6c 55 4c 62 58 43 76 43 54 2e 42 61 6d 70 45 52 58 57 64 41 39 6a 57 4c 73 69 74 6f } //1 dPqLCOBUxlULbXCvCT.BampERXWdA9jWLsito
		$a_01_2 = {6e 56 46 39 61 68 61 50 77 45 41 41 33 45 65 63 65 76 2e 50 77 53 78 6b 79 6c 61 36 56 6e 33 48 38 69 6d 4f 49 } //1 nVF9ahaPwEAA3Eecev.PwSxkyla6Vn3H8imOI
		$a_01_3 = {45 48 37 50 72 51 67 62 37 6c 77 32 47 33 78 67 58 50 } //1 EH7PrQgb7lw2G3xgXP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
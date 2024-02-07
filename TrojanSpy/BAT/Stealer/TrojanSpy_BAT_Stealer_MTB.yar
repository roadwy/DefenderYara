
rule TrojanSpy_BAT_Stealer_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 91 6f 90 01 03 0a 00 00 07 25 17 59 0b 16 fe 90 01 01 0c 08 2d e7 90 00 } //01 00 
		$a_01_1 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_2 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_80_3 = {68 74 74 70 3a 2f 2f 31 30 37 2e 31 37 33 2e 31 39 31 2e 31 32 33 2f 73 77 69 66 74 2f 46 65 70 76 69 75 65 65 68 5f 44 6a 65 73 62 71 71 69 2e 6a 70 67 } //http://107.173.191.123/swift/Fepviueeh_Djesbqqi.jpg  00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_AveMariaRat_MF_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRat.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 34 00 37 00 32 00 30 00 35 00 31 00 32 00 33 00 32 00 30 00 31 00 34 00 35 00 39 00 38 00 31 00 34 00 34 00 2f 00 90 02 60 2e 00 6a 00 70 00 67 00 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_2 = {2f 00 43 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 } //01 00  /C timeout
		$a_01_3 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_4 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_5 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_7 = {4d 61 67 69 63 4c 69 6e 65 34 4e 58 } //00 00  MagicLine4NX
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_SpyNoon_KLNG_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.KLNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 02 00 "
		
	strings :
		$a_81_0 = {54 6f 53 74 72 69 6e 67 } //02 00  ToString
		$a_81_1 = {00 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 00 } //02 00  堀塘塘塘塘塘塘塘塘塘塘X
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //02 00  FromBase64CharArray
		$a_81_3 = {54 6f 43 68 61 72 41 72 72 61 79 } //02 00  ToCharArray
		$a_81_4 = {00 52 41 57 00 } //02 00 
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //02 00  DebuggableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //02 00  DebuggerNonUserCodeAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //02 00  DebuggerHiddenAttribute
		$a_81_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerBrowsableAttribute
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_AgentTesla_HX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 10 00 00 14 00 "
		
	strings :
		$a_81_0 = {6e 6d 73 66 6d 65 61 69 65 } //14 00  nmsfmeaie
		$a_81_1 = {78 61 73 63 61 66 67 66 67 } //14 00  xascafgfg
		$a_81_2 = {78 63 7a 64 63 73 61 73 73 64 } //14 00  xczdcsassd
		$a_81_3 = {66 61 33 77 66 65 66 } //14 00  fa3wfef
		$a_81_4 = {6c 61 73 65 66 65 77 32 } //14 00  lasefew2
		$a_81_5 = {6d 78 63 76 6e 73 77 64 73 } //14 00  mxcvnswds
		$a_81_6 = {78 63 7a 63 65 63 77 65 77 71 32 } //14 00  xczcecwewq2
		$a_81_7 = {7a 63 65 71 61 77 64 32 31 } //01 00  zceqawd21
		$a_81_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_9 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_81_10 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_11 = {44 6f 77 6e 6c 6f 61 64 } //01 00  Download
		$a_81_12 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_13 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00  ShellExecute
		$a_81_14 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_15 = {52 65 61 64 54 6f 45 6e 64 } //00 00  ReadToEnd
	condition:
		any of ($a_*)
 
}
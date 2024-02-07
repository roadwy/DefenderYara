
rule Trojan_BAT_RexCry_DA_MTB{
	meta:
		description = "Trojan:BAT/RexCry.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 07 00 00 05 00 "
		
	strings :
		$a_81_0 = {57 72 69 74 65 20 70 61 74 68 20 74 6f 20 66 69 6c 65 20 74 6f 20 65 6e 63 72 79 70 74 } //05 00  Write path to file to encrypt
		$a_81_1 = {73 76 63 68 6f 73 74 2e 65 78 65 } //05 00  svchost.exe
		$a_81_2 = {50 61 74 74 65 72 6e 41 74 } //05 00  PatternAt
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //05 00  FromBase64String
		$a_81_4 = {52 65 78 43 72 79 } //01 00  RexCry
		$a_81_5 = {4d 41 53 46 47 4b 55 } //01 00  MASFGKU
		$a_81_6 = {4d 41 53 46 55 43 4b } //00 00  MASFUCK
	condition:
		any of ($a_*)
 
}
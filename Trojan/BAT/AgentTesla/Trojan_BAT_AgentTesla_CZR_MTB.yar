
rule Trojan_BAT_AgentTesla_CZR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 } //01 00  System.Convert
		$a_01_1 = {67 00 6e 00 69 00 72 00 74 00 53 00 34 00 36 00 65 00 73 00 61 00 42 00 6d 00 6f 00 72 00 46 00 } //01 00  gnirtS46esaBmorF
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_01_3 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_4 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_01_5 = {58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 } //01 00  XXXXXXXXXXXXX
		$a_01_6 = {47 00 2d 00 65 00 2d 00 74 00 2d 00 4d 00 2d 00 65 00 2d 00 74 00 2d 00 68 00 2d 00 6f 00 2d 00 64 00 } //01 00  G-e-t-M-e-t-h-o-d
		$a_01_7 = {49 00 2d 00 2d 00 6e 00 2d 00 2d 00 76 00 2d 00 2d 00 6f 00 2d 00 2d 00 6b 00 2d 00 2d 00 65 00 } //00 00  I--n--v--o--k--e
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_AgentTesla_JXC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 00 2d 00 65 00 2d 00 74 00 2d 00 4d 00 2d 00 65 00 2d 00 74 00 2d 00 68 00 2d 00 6f 00 2d 00 64 00 } //01 00  G-e-t-M-e-t-h-o-d
		$a_81_1 = {49 00 2d 00 2d 00 6e 00 2d 00 2d 00 76 00 2d 00 2d 00 6f 00 2d 00 2d 00 6b 00 2d 00 2d 00 65 00 } //01 00  I--n--v--o--k--e
		$a_01_2 = {58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 } //01 00  XXXXXXXXXXXXX
		$a_01_3 = {67 00 6e 00 69 00 72 00 74 00 53 00 34 00 36 00 65 00 73 00 61 00 42 00 6d 00 6f 00 72 00 46 00 } //01 00  gnirtS46esaBmorF
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_01_5 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_6 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //00 00  GetTypeFromHandle
	condition:
		any of ($a_*)
 
}
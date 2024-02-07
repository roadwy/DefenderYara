
rule Trojan_BAT_AgentTesla_JZP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 13 04 06 11 04 28 90 01 03 0a 07 da 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0a 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 05 11 05 2d ca 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_2 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 } //01 00  SuspendLayout
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 } //00 00  StrReverse
	condition:
		any of ($a_*)
 
}
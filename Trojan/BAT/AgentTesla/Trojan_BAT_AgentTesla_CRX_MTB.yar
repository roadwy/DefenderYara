
rule Trojan_BAT_AgentTesla_CRX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 0a 01 00 5d 07 09 20 00 0a 01 00 5d 91 08 09 1f 16 5d 6f 90 01 03 0a 61 07 09 17 58 20 00 0a 01 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d b7 90 00 } //01 00 
		$a_81_1 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_3 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_4 = {4c 00 69 00 74 00 74 00 6c 00 65 00 47 00 61 00 6d 00 65 00 42 00 6f 00 78 00 } //01 00  LittleGameBox
		$a_01_5 = {35 00 38 00 34 00 48 00 35 00 34 00 38 00 43 00 52 00 38 00 48 00 53 00 47 00 45 00 4a 00 53 00 34 00 37 00 43 00 34 00 34 00 48 00 } //00 00  584H548CR8HSGEJS47C44H
	condition:
		any of ($a_*)
 
}
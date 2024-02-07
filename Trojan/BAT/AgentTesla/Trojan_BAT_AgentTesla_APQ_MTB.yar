
rule Trojan_BAT_AgentTesla_APQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.APQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 11 04 11 07 90 01 05 13 08 11 08 90 01 05 13 09 08 06 11 09 b4 9c 11 07 17 d6 13 07 11 07 11 06 31 d9 90 00 } //01 00 
		$a_81_1 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_81_2 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_81_3 = {53 69 6d 70 6c 65 55 49 2e 4d 44 49 } //00 00  SimpleUI.MDI
	condition:
		any of ($a_*)
 
}
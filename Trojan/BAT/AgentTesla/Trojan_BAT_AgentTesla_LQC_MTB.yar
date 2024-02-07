
rule Trojan_BAT_AgentTesla_LQC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 70 66 73 62 61 6e 6b 67 72 6f 75 70 2e 63 6f 6d 2f } //01 00  http://pfsbankgroup.com/
		$a_81_1 = {55 77 42 30 41 47 45 41 63 67 42 30 41 43 30 41 55 77 42 73 41 47 55 41 5a 51 42 77 41 43 41 41 4c 51 42 54 41 47 55 41 59 77 42 76 41 47 34 41 5a 41 42 7a 41 43 41 41 4d 51 41 75 41 44 55 41 } //01 00  UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMQAuADUA
		$a_01_2 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_4 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_81_5 = {70 6f 77 65 72 73 68 65 6c 6c } //01 00  powershell
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}
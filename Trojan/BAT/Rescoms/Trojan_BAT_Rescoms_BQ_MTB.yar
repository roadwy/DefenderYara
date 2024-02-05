
rule Trojan_BAT_Rescoms_BQ_MTB{
	meta:
		description = "Trojan:BAT/Rescoms.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {4f 6e 53 74 72 65 73 73 4c 65 76 65 6c 45 78 63 65 65 64 65 64 } //OnStressLevelExceeded  03 00 
		$a_80_1 = {70 6f 77 65 72 73 68 65 6c 6c } //powershell  03 00 
		$a_80_2 = {54 65 73 74 2d 4e 65 74 43 6f 6e 6e 65 63 74 69 6f 6e } //Test-NetConnection  03 00 
		$a_80_3 = {61 64 64 5f 53 74 72 65 73 73 4c 69 6d 69 74 45 78 63 65 65 64 65 64 } //add_StressLimitExceeded  03 00 
		$a_80_4 = {35 62 77 42 75 41 41 41 41 4d 51 41 75 41 44 41 41 4c 67 41 77 41 43 34 41 4d 41 41 41 41 44 67 41 43 41 41 42 41 45 45 41 63 77 42 7a 41 47 55 41 62 51 42 69 41 47 77 41 65 51 41 67 41 46 59 41 5a 51 42 79 41 48 4d 41 } //5bwBuAAAAMQAuADAALgAwAC4AMAAAADgACAABAEEAcwBzAGUAbQBiAGwAeQAgAFYAZQByAHMA  03 00 
		$a_80_5 = {45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //Explorer_Server  03 00 
		$a_80_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  00 00 
	condition:
		any of ($a_*)
 
}
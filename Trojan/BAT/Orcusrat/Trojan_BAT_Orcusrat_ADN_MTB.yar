
rule Trojan_BAT_Orcusrat_ADN_MTB{
	meta:
		description = "Trojan:BAT/Orcusrat.ADN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 18 00 0a 00 00 05 00 "
		
	strings :
		$a_80_0 = {4f 72 63 55 53 } //OrcUS  05 00 
		$a_80_1 = {4f 72 63 55 53 2e 57 61 74 63 68 64 6f 67 } //OrcUS.Watchdog  04 00 
		$a_80_2 = {4b 69 6c 6c 42 75 74 74 6f 6e 5f 43 6c 69 63 6b } //KillButton_Click  04 00 
		$a_80_3 = {67 45 54 5f 52 65 6d 6f 74 65 45 6e 64 50 6f 69 6e 74 } //gET_RemoteEndPoint  04 00 
		$a_80_4 = {44 69 73 61 62 6c 65 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 50 72 6f 6d 70 74 } //DisableInstallationPrompt  04 00 
		$a_80_5 = {67 45 54 5f 6b 45 59 4c 6f 67 67 65 72 53 65 72 76 69 63 65 } //gET_kEYLoggerService  04 00 
		$a_80_6 = {67 45 54 5f 53 65 72 76 65 72 43 6f 6e 6e 65 63 74 69 6f 6e } //gET_ServerConnection  04 00 
		$a_80_7 = {67 45 54 5f 52 65 71 75 69 72 65 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 50 72 69 76 69 6c 65 67 65 73 } //gET_RequireAdministratorPrivileges  04 00 
		$a_80_8 = {67 45 54 46 72 65 65 54 65 6d 70 46 69 6c 65 4e 61 6d 65 } //gETFreeTempFileName  04 00 
		$a_80_9 = {67 45 54 5f 54 61 73 6b 4e 61 6d 65 } //gET_TaskName  00 00 
	condition:
		any of ($a_*)
 
}
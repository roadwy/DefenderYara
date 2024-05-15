
rule Trojan_BAT_DarkStealer_RHB_MTB{
	meta:
		description = "Trojan:BAT/DarkStealer.RHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 00 74 00 6d 00 61 00 6e 00 6e 00 67 00 2e 00 6e 00 6f 00 2d 00 69 00 70 00 2e 00 69 00 6e 00 66 00 6f 00 } //01 00  atmanng.no-ip.info
		$a_00_1 = {53 00 65 00 6c 00 65 00 63 00 74 00 53 00 65 00 72 00 76 00 65 00 72 00 } //01 00  SelectServer
		$a_01_2 = {64 61 74 61 5f 70 61 73 73 77 6f 72 64 } //01 00  data_password
		$a_00_3 = {4f 00 72 00 64 00 65 00 72 00 20 00 62 00 79 00 20 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 2e 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //01 00  Order by Accounts.System
		$a_00_4 = {43 00 68 00 69 00 6e 00 65 00 73 00 65 00 4e 00 61 00 6d 00 65 00 20 00 46 00 72 00 6f 00 6d 00 20 00 55 00 73 00 65 00 72 00 4c 00 69 00 73 00 74 00 } //01 00  ChineseName From UserList
		$a_01_5 = {57 46 43 4c 2e 53 65 6c 65 63 74 53 65 72 76 65 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00  WFCL.SelectServer.resources
		$a_01_6 = {53 79 6e 63 44 61 74 61 28 41 4e 2d 4e 41 53 29 } //01 00  SyncData(AN-NAS)
		$a_01_7 = {41 4e 2d 53 65 72 76 65 72 } //01 00  AN-Server
		$a_01_8 = {57 46 43 4c 2e 70 64 62 } //02 00  WFCL.pdb
		$a_03_9 = {50 45 00 00 4c 01 03 90 01 11 0b 01 50 90 01 05 00 76 02 90 01 07 05 00 00 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
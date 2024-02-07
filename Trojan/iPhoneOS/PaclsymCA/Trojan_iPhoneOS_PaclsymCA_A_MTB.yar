
rule Trojan_iPhoneOS_PaclsymCA_A_MTB{
	meta:
		description = "Trojan:iPhoneOS/PaclsymCA.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 73 61 75 72 69 6b 2e 43 79 64 69 61 } //01 00  com.saurik.Cydia
		$a_00_1 = {2f 65 74 63 2f 61 70 74 2f 73 6f 75 72 63 65 73 2e 6c 69 73 74 2e 64 2f 63 79 64 69 61 2e 6c 69 73 74 } //01 00  /etc/apt/sources.list.d/cydia.list
		$a_00_2 = {53 65 74 43 79 64 69 61 56 69 73 69 62 69 6c 69 74 79 50 72 6f 63 65 73 73 6f 72 } //01 00  SetCydiaVisibilityProcessor
		$a_00_3 = {50 61 73 73 77 6f 72 64 43 61 70 74 75 72 65 4d 61 6e 61 67 65 72 } //01 00  PasswordCaptureManager
		$a_00_4 = {52 65 6d 6f 74 65 43 6d 64 44 61 74 61 } //01 00  RemoteCmdData
		$a_00_5 = {53 79 6e 63 53 6e 61 70 73 68 6f 74 52 75 6c 65 73 4d 53 47 } //00 00  SyncSnapshotRulesMSG
	condition:
		any of ($a_*)
 
}
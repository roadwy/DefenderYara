
rule TrojanSpy_MacOS_GKChain_D_MTB{
	meta:
		description = "TrojanSpy:MacOS/GKChain.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,09 00 09 00 07 00 00 06 00 "
		
	strings :
		$a_00_0 = {75 73 61 2e 34 6a 72 62 37 78 6e 38 72 78 73 6e 38 6f 34 6c 67 68 6b 37 6c 78 36 76 6e 76 6e 76 61 7a 76 61 } //01 00  usa.4jrb7xn8rxsn8o4lghk7lx6vnvnvazva
		$a_00_1 = {4a 4b 45 6e 63 72 79 70 74 20 64 6f 45 6e 63 72 79 70 74 53 74 72 } //01 00  JKEncrypt doEncryptStr
		$a_00_2 = {2e 6b 65 79 63 68 61 69 6e } //01 00  .keychain
		$a_00_3 = {63 6f 6d 70 6c 65 74 69 6f 6e 54 61 73 6b 43 6f 6e 74 61 69 6e 73 47 6b 65 79 53 74 61 6e 64 61 72 64 48 6f 77 3a 61 62 73 6f 6c 75 74 65 46 69 6c 65 50 61 74 68 } //01 00  completionTaskContainsGkeyStandardHow:absoluteFilePath
		$a_00_4 = {6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 69 65 73 52 65 73 70 6f 6e 73 65 4f 63 74 65 74 } //01 00  ncryptDirectoriesResponseOctet
		$a_00_5 = {70 6f 73 74 44 61 74 61 57 69 74 68 45 6e 63 72 79 70 74 33 64 65 73 44 61 74 61 } //01 00  postDataWithEncrypt3desData
		$a_00_6 = {64 65 76 69 63 65 49 64 65 6e 74 69 74 79 53 65 72 76 65 72 43 68 65 63 6b 3a } //00 00  deviceIdentityServerCheck:
	condition:
		any of ($a_*)
 
}
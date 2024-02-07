
rule TrojanSpy_MacOS_GKChain_A_MTB{
	meta:
		description = "TrojanSpy:MacOS/GKChain.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {75 73 61 2e 34 6a 72 62 37 78 6e 38 72 78 73 6e 38 6f 34 6c 67 68 6b 37 6c 78 36 76 6e 76 6e 76 61 7a 76 61 } //01 00  usa.4jrb7xn8rxsn8o4lghk7lx6vnvnvazva
		$a_01_1 = {4a 4b 45 6e 63 72 79 70 74 20 64 6f 45 6e 63 72 79 70 74 53 74 72 } //01 00  JKEncrypt doEncryptStr
		$a_01_2 = {4a 4b 45 6e 63 72 79 70 74 20 64 6f 45 6e 63 72 79 70 74 48 65 78 } //01 00  JKEncrypt doEncryptHex
		$a_01_3 = {2e 6b 65 79 63 68 61 69 6e } //01 00  .keychain
		$a_01_4 = {25 40 2f 4d 6f 62 69 6c 65 44 65 76 69 63 65 2f 50 72 6f 76 69 73 69 6f 6e 69 6e 67 20 50 72 6f 66 69 6c 65 73 } //00 00  %@/MobileDevice/Provisioning Profiles
	condition:
		any of ($a_*)
 
}
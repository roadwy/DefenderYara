
rule Trojan_MacOS_SuspKeyChainAccess_AX{
	meta:
		description = "Trojan:MacOS/SuspKeyChainAccess.AX,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {4a 43 5f 42 55 4e 44 4c 45 5f 49 44 } //2 JC_BUNDLE_ID
		$a_00_1 = {72 61 6e 72 6f 6b } //2 ranrok
		$a_00_2 = {4a 43 5f 57 4f 52 4b 46 4c 4f 57 5f 4d 53 47 } //2 JC_WORKFLOW_MSG
		$a_00_3 = {2f 4c 69 62 72 61 72 79 2f 4b 65 79 63 68 61 69 6e 73 2f 53 79 73 74 65 6d 2e 6b 65 79 63 68 61 69 6e } //1 /Library/Keychains/System.keychain
		$a_00_4 = {2f 4c 69 62 72 61 72 79 2f 4b 65 79 63 68 61 69 6e 73 2f 6c 6f 67 69 6e 2e 6b 65 79 63 68 61 69 6e 2d 64 62 } //1 /Library/Keychains/login.keychain-db
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}
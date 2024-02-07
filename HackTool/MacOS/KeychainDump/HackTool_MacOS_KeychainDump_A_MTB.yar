
rule HackTool_MacOS_KeychainDump_A_MTB{
	meta:
		description = "HackTool:MacOS/KeychainDump.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5b 2d 5d 20 43 6f 75 6c 64 20 6e 6f 74 20 61 6c 6c 6f 63 61 74 65 20 6d 65 6d 6f 72 79 20 66 6f 72 20 6b 65 79 20 73 65 61 72 63 68 } //01 00  [-] Could not allocate memory for key search
		$a_00_1 = {5b 2d 5d 20 54 68 65 20 74 61 72 67 65 74 20 66 69 6c 65 20 69 73 20 6e 6f 74 20 61 20 6b 65 79 63 68 61 69 6e 20 66 69 6c 65 } //01 00  [-] The target file is not a keychain file
		$a_00_2 = {5b 2a 5d 20 54 72 79 69 6e 67 20 74 6f 20 64 65 63 72 79 70 74 20 77 72 61 70 70 69 6e 67 20 6b 65 79 20 69 6e 20 25 73 } //01 00  [*] Trying to decrypt wrapping key in %s
		$a_00_3 = {5f 66 69 6e 64 5f 6f 72 5f 63 72 65 61 74 65 5f 63 72 65 64 65 6e 74 69 61 6c 73 } //01 00  _find_or_create_credentials
		$a_00_4 = {25 73 2f 4c 69 62 72 61 72 79 2f 4b 65 79 63 68 61 69 6e 73 2f 6c 6f 67 69 6e 2e 6b 65 79 63 68 61 69 6e } //00 00  %s/Library/Keychains/login.keychain
	condition:
		any of ($a_*)
 
}
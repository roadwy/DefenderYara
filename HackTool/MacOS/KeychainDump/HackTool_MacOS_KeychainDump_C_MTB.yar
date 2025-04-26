
rule HackTool_MacOS_KeychainDump_C_MTB{
	meta:
		description = "HackTool:MacOS/KeychainDump.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 65 79 63 68 61 69 6e 5f 64 75 6d 70 65 72 } //1 keychain_dumper
		$a_01_1 = {2f 76 61 72 2f 4b 65 79 63 68 61 69 6e 73 2f 6b 65 79 63 68 61 69 6e 2d 32 2e 64 62 } //1 /var/Keychains/keychain-2.db
		$a_01_2 = {64 75 6d 70 4b 65 79 63 68 61 69 6e 45 6e 74 69 74 6c 65 6d 65 6e 74 73 } //1 dumpKeychainEntitlements
		$a_01_3 = {44 75 6d 70 20 49 6e 74 65 72 6e 65 74 20 50 61 73 73 77 6f 72 64 73 } //1 Dump Internet Passwords
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}

rule Trojan_iPhoneOS_TraingleDB_A_MTB{
	meta:
		description = "Trojan:iPhoneOS/TraingleDB.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 6e 6d 75 6e 67 65 48 65 78 53 74 72 69 6e 67 } //01 00  unmungeHexString
		$a_00_1 = {43 52 50 77 72 49 6e 66 6f } //01 00  CRPwrInfo
		$a_00_2 = {43 52 43 6f 6e 66 69 67 } //01 00  CRConfig
		$a_00_3 = {43 52 58 43 6f 6e 66 69 67 75 72 65 44 42 53 65 72 76 65 72 } //00 00  CRXConfigureDBServer
	condition:
		any of ($a_*)
 
}
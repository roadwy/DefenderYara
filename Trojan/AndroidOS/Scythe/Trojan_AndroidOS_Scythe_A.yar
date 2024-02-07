
rule Trojan_AndroidOS_Scythe_A{
	meta:
		description = "Trojan:AndroidOS/Scythe.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 72 6f 6e 67 45 61 6d 69 6c } //01 00  wrongEamil
		$a_01_1 = {6d 65 73 73 61 67 65 46 6f 6c 64 65 72 52 65 74 72 69 65 76 65 } //01 00  messageFolderRetrieve
		$a_01_2 = {46 61 63 65 62 6f 6f 6b 41 75 74 68 65 6e 74 69 63 61 74 6f 72 53 65 72 76 69 63 65 20 3a 20 63 6f 6e 66 69 72 6d 43 72 65 64 65 6e 74 69 61 6c 73 } //01 00  FacebookAuthenticatorService : confirmCredentials
		$a_01_3 = {53 6e 73 41 63 63 6f 75 6e 74 20 44 45 42 55 47 20 4d 4f 44 45 20 4f 4e } //00 00  SnsAccount DEBUG MODE ON
	condition:
		any of ($a_*)
 
}
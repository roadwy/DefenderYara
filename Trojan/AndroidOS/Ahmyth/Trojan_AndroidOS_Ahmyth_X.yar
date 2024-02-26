
rule Trojan_AndroidOS_Ahmyth_X{
	meta:
		description = "Trojan:AndroidOS/Ahmyth.X,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 3d 3d 3a 73 65 6e 64 52 65 67 69 73 74 72 61 74 69 6f 6e 54 6f 53 65 72 76 65 72 } //01 00  ===:sendRegistrationToServer
		$a_01_1 = {43 4c 41 53 53 5f 4f 50 50 41 53 53 57 4f 52 44 5f 50 49 4e } //00 00  CLASS_OPPASSWORD_PIN
	condition:
		any of ($a_*)
 
}
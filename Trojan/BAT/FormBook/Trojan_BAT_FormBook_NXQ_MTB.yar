
rule Trojan_BAT_FormBook_NXQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 6b 34 31 55 61 32 41 46 75 35 50 41 4e 4d 4b 69 74 2e 61 62 69 4a 50 6d 66 42 66 54 4c 36 69 4c 66 6d 61 57 } //01 00  sk41Ua2AFu5PANMKit.abiJPmfBfTL6iLfmaW
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}
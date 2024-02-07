
rule Trojan_BAT_NetWire_AD_MTB{
	meta:
		description = "Trojan:BAT/NetWire.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 50 00 72 00 6f 00 78 00 79 00 } //01 00  InternetProxy
		$a_01_1 = {4e 65 74 57 69 72 65 } //01 00  NetWire
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4e 65 74 57 69 72 65 } //01 00  SOFTWARE\NetWire
		$a_01_3 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //01 00  encryptedUsername
		$a_01_4 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //01 00  encryptedPassword
		$a_01_5 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //01 00  encrypted_key
		$a_01_6 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //00 00  Google\Chrome\User Data\Default\Login Data
	condition:
		any of ($a_*)
 
}
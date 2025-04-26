
rule Trojan_BAT_Stealer_NL_MTB{
	meta:
		description = "Trojan:BAT/Stealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {65 6d 6d 61 6e 6f 75 69 6c 5f 6d 61 73 74 72 61 6e 74 6f 6e 61 6b 69 73 5f 69 6e 64 69 76 69 64 75 61 6c 50 72 6f 6a 65 63 74 } //emmanouil_mastrantonakis_individualProject  1
		$a_80_1 = {40 50 61 73 73 77 6f 72 64 } //@Password  1
		$a_80_2 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //MD5CryptoServiceProvider  1
		$a_80_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
		$a_80_4 = {65 6d 6d 61 6e 6f 75 69 6c 6d 61 73 74 72 61 6e 74 6f 6e 61 6b 69 73 69 6e 64 69 76 69 64 75 61 6c 50 72 6f 6a 65 63 74 } //emmanouilmastrantonakisindividualProject  1
		$a_80_5 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //System.Security.Cryptography  1
		$a_80_6 = {3c 50 61 73 73 77 6f 72 64 3e 6b 5f 5f 42 61 63 6b 69 6e 67 46 69 65 6c 64 } //<Password>k__BackingField  1
		$a_80_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //DebuggerBrowsableState  1
		$a_80_8 = {28 46 69 72 73 74 4e 61 6d 65 2c 20 4c 61 73 74 4e 61 6d 65 2c 20 52 6f 6c 65 2c 20 45 6d 61 69 6c 2c 20 50 68 6f 6e 65 2c 20 55 73 65 72 6e 61 6d 65 2c 20 50 61 73 73 77 6f 72 64 29 } //(FirstName, LastName, Role, Email, Phone, Username, Password)  1
		$a_80_9 = {54 65 73 74 46 69 6c 65 73 5c 41 6c 6c 4d 65 73 73 61 67 65 73 2e 74 78 74 } //TestFiles\AllMessages.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=10
 
}

rule Trojan_BAT_InfoStealer_ARA_MTB{
	meta:
		description = "Trojan:BAT/InfoStealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0f 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 76 65 4e 65 78 74 } //1 MoveNext
		$a_01_1 = {53 79 73 74 65 6d 2e 54 65 78 74 } //1 System.Text
		$a_01_2 = {52 65 61 64 41 6c 6c 54 65 78 74 } //1 ReadAllText
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_01_5 = {52 65 61 64 4b 65 79 } //1 ReadKey
		$a_01_6 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_80_7 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //\Google\Chrome\User Data  1
		$a_80_8 = {5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //\Default\Login Data  1
		$a_80_9 = {5c 4c 6f 63 61 6c 20 53 74 61 74 65 } //\Local State  1
		$a_80_10 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //encrypted_key  1
		$a_80_11 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 6c 6f 67 69 6e 73 } //select * from logins  2
		$a_80_12 = {70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 } //password_value  2
		$a_80_13 = {75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 } //username_value  2
		$a_80_14 = {53 74 72 69 6e 67 46 69 6c 65 49 6e 66 6f } //StringFileInfo  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*2+(#a_80_12  & 1)*2+(#a_80_13  & 1)*2+(#a_80_14  & 1)*1) >=18
 
}
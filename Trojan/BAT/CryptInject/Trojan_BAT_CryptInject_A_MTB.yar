
rule Trojan_BAT_CryptInject_A_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73 } //1 get_WebServices
		$a_00_1 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 } //1 get_Computer
		$a_00_2 = {67 65 74 5f 55 73 65 72 } //1 get_User
		$a_00_3 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //1 Rfc2898DeriveBytes
		$a_00_4 = {67 65 74 5f 4b 65 79 53 69 7a 65 } //1 get_KeySize
		$a_00_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_00_6 = {52 65 67 69 73 74 72 79 4b 65 79 } //1 RegistryKey
		$a_00_7 = {53 65 74 56 61 6c 75 65 } //1 SetValue
		$a_00_8 = {43 72 65 61 74 65 53 75 62 4b 65 79 } //1 CreateSubKey
		$a_02_9 = {43 3a 5c 55 73 65 72 73 5c 59 65 74 69 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c [0-0a] 2e 70 64 62 } //1
		$a_00_10 = {47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 } //1 GetProcessesByName
		$a_00_11 = {4b 69 6c 6c } //1 Kill
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_02_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1) >=12
 
}
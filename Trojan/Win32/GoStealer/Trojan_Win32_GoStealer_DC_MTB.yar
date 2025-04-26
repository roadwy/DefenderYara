
rule Trojan_Win32_GoStealer_DC_MTB{
	meta:
		description = "Trojan:Win32/GoStealer.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,36 00 36 00 05 00 00 "
		
	strings :
		$a_81_0 = {47 6f 6f 67 6c 65 20 43 68 72 6f 6d 65 20 43 72 65 64 69 74 20 43 61 72 64 73 } //50 Google Chrome Credit Cards
		$a_81_1 = {4c 6f 67 69 6e 20 44 61 74 61 } //1 Login Data
		$a_81_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 } //1 Application Data
		$a_81_3 = {55 73 65 72 20 44 61 74 61 } //1 User Data
		$a_81_4 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 encrypted_key
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=54
 
}
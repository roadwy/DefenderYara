
rule TrojanSpy_Win32_Malatiz_A{
	meta:
		description = "TrojanSpy:Win32/Malatiz.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {53 45 4c 45 43 54 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 2c 20 73 69 67 6e 6f 6e 5f 72 65 61 6c 6d 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //SELECT username_value, password_value, signon_realm FROM logins  1
		$a_80_1 = {5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //\User Data\Default\Login Data  1
		$a_80_2 = {54 68 69 73 20 43 6f 6d 70 75 74 65 72 20 49 53 20 6e 6f 74 20 56 69 72 75 73 65 64 } //This Computer IS not Virused  1
		$a_80_3 = {7b 54 65 6d 70 2d 30 30 2d 61 61 2d 31 32 33 2d 6d 72 2d 62 62 62 7d } //{Temp-00-aa-123-mr-bbb}  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
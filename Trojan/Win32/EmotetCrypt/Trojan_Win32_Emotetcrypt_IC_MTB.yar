
rule Trojan_Win32_Emotetcrypt_IC_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {76 29 29 59 6f 4f 61 59 74 69 68 75 41 35 78 6a 66 65 34 41 51 63 21 6e 65 34 40 49 79 45 4a 77 50 39 33 29 26 44 38 30 39 21 5e 24 35 6a 33 63 42 72 7a 67 6a 2a 53 43 24 51 34 76 35 29 21 6f 49 62 58 23 72 69 78 36 77 55 23 2a 42 47 43 4b 25 6d 21 4d 26 72 77 36 63 54 69 3e 64 24 29 74 52 21 43 6d 4d 39 2a 25 40 30 76 3c 44 4b 70 50 78 4f 65 } //01 00  v))YoOaYtihuA5xjfe4AQc!ne4@IyEJwP93)&D809!^$5j3cBrzgj*SC$Q4v5)!oIbX#rix6wU#*BGCK%m!M&rw6cTi>d$)tR!CmM9*%@0v<DKpPxOe
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}
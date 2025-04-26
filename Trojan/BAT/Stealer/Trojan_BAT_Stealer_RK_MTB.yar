
rule Trojan_BAT_Stealer_RK_MTB{
	meta:
		description = "Trojan:BAT/Stealer.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 64 55 49 50 72 6f 6d 70 74 46 6f 72 43 72 65 64 65 6e 74 69 61 6c 73 } //1 CredUIPromptForCredentials
		$a_80_1 = {55 53 45 52 4e 41 4d 45 5f 54 41 52 47 45 54 5f 43 52 45 44 45 4e 54 49 41 4c 53 } //USERNAME_TARGET_CREDENTIALS  1
		$a_01_2 = {43 72 65 61 74 65 52 75 6e 73 70 61 63 65 } //1 CreateRunspace
		$a_01_3 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_81_4 = {63 47 39 33 5a 58 4a 7a 61 47 56 73 62 43 35 6c 65 47 55 67 4c 57 56 34 5a 57 4e 31 64 47 6c 76 62 6e 42 76 62 47 6c 6a 65 53 42 69 65 58 42 68 63 33 4d 67 63 33 52 68 63 6e 51 74 63 32 78 6c 5a 58 41 67 4e 53 41 37 49 43 35 63 4d 53 35 30 65 48 51 4e 43 67 30 4b 44 51 6f 4e 43 67 3d 3d } //1 cG93ZXJzaGVsbC5leGUgLWV4ZWN1dGlvbnBvbGljeSBieXBhc3Mgc3RhcnQtc2xlZXAgNSA7IC5cMS50eHQNCg0KDQoNCg==
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
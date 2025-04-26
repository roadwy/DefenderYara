
rule PWS_Win32_VaultDumper_GG_MTB{
	meta:
		description = "PWS:Win32/VaultDumper.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //encryptedUsername  1
		$a_80_1 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //encryptedPassword  1
		$a_80_2 = {25 73 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //%s\Mozilla\Firefox\profiles.ini  1
		$a_80_3 = {6c 6f 67 69 6e 73 } //logins  1
		$a_80_4 = {68 6f 73 74 6e 61 6d 65 } //hostname  1
		$a_80_5 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //SELECT * FROM moz_logins  1
		$a_80_6 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //SELECT * FROM logins  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
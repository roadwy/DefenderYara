
rule Trojan_BAT_Stealerc_GPXA_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.GPXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_81_0 = {73 65 6e 64 44 6f 63 75 6d 65 6e 74 3f 63 68 61 74 5f 69 64 3d } //2 sendDocument?chat_id=
		$a_81_1 = {1b 49 00 4d 00 41 00 50 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 00 1b 50 00 4f 00 50 00 33 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 } //2
		$a_01_2 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 5f 00 6b 00 65 00 79 00 22 00 3a 00 22 00 28 00 2e 00 2a 00 3f 00 29 } //1
		$a_81_3 = {4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 Microsoft\Edge\User Data\Default\Login Data
		$a_81_4 = {6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 logins.json
		$a_81_5 = {54 68 75 6e 64 65 72 62 69 72 64 5c 50 72 6f 66 69 6c 65 73 } //1 Thunderbird\Profiles
		$a_81_6 = {6e 73 73 33 2e 64 6c 6c } //1 nss3.dll
		$a_81_7 = {50 4b 31 31 53 44 52 5f 44 65 63 72 79 70 74 } //1 PK11SDR_Decrypt
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=10
 
}
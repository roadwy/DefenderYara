
rule PWS_BAT_Stealgen_GF_MTB{
	meta:
		description = "PWS:BAT/Stealgen.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0b 00 00 "
		
	strings :
		$a_80_0 = {53 74 65 61 6c 65 72 } //Stealer  10
		$a_80_1 = {6c 6f 67 69 6e 73 } //logins  1
		$a_80_2 = {6f 72 69 67 69 6e 5f 75 72 6c } //origin_url  1
		$a_80_3 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 22 3a 22 28 2e 2a 3f 29 } //encrypted_key":"(.*?)  1
		$a_80_4 = {48 65 6c 6c 6f 20 41 64 6d 69 6e } //Hello Admin  1
		$a_80_5 = {50 61 73 73 77 6f 72 64 73 2e } //Passwords.  1
		$a_80_6 = {4e 6f 72 64 56 50 4e } //NordVPN  1
		$a_80_7 = {2f 2f 73 65 74 74 69 6e 67 5b 40 6e 61 6d 65 3d 27 55 73 65 72 6e 61 6d 65 27 5d 2f 76 61 6c 75 65 } ////setting[@name='Username']/value  1
		$a_80_8 = {2f 2f 73 65 74 74 69 6e 67 5b 40 6e 61 6d 65 3d 27 50 61 73 73 77 6f 72 64 27 5d 2f 76 61 6c 75 65 } ////setting[@name='Password']/value  1
		$a_80_9 = {43 68 72 6f 6d 65 } //Chrome  1
		$a_80_10 = {53 51 4c 69 74 65 } //SQLite  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=19
 
}
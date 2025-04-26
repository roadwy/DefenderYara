
rule Trojan_Win64_StrelaStealer_GPAX_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {73 74 72 65 6c 61 } //1 strela
		$a_81_1 = {2f 73 65 72 76 65 72 2e 70 68 70 } //1 /server.php
		$a_81_2 = {49 4d 41 50 20 53 65 72 76 65 72 } //1 IMAP Server
		$a_81_3 = {49 4d 41 50 20 55 73 65 72 } //1 IMAP User
		$a_81_4 = {49 4d 41 50 20 50 61 73 73 77 6f 72 64 } //1 IMAP Password
		$a_81_5 = {54 68 75 6e 64 65 72 62 69 72 64 5c 50 72 6f 66 69 6c 65 73 } //1 Thunderbird\Profiles
		$a_81_6 = {25 73 25 73 5c 6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 %s%s\logins.json
		$a_81_7 = {25 73 25 73 5c 6b 65 79 34 2e 64 62 } //1 %s%s\key4.db
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
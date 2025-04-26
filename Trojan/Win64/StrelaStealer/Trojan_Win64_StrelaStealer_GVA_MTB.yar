
rule Trojan_Win64_StrelaStealer_GVA_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 09 00 00 "
		
	strings :
		$a_81_0 = {49 4d 41 50 20 53 65 72 76 65 72 } //1 IMAP Server
		$a_81_1 = {49 4d 41 50 20 55 73 65 72 } //1 IMAP User
		$a_01_2 = {2f 75 70 2e 70 68 70 } //1 /up.php
		$a_01_3 = {5c 6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 \logins.json
		$a_81_4 = {49 4d 41 50 20 50 61 73 73 77 6f 72 64 } //1 IMAP Password
		$a_01_5 = {5c 6b 65 79 34 2e 64 62 } //1 \key4.db
		$a_01_6 = {63 68 65 6f 6c 6c 69 6d 61 } //1 cheollima
		$a_01_7 = {5c 54 68 75 6e 64 65 72 62 69 72 64 5c 50 72 6f 66 69 6c 65 73 5c } //1 \Thunderbird\Profiles\
		$a_02_8 = {39 34 2e 31 35 39 2e 31 31 33 2e [0-03] 00 } //3
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_02_8  & 1)*3) >=11
 
}
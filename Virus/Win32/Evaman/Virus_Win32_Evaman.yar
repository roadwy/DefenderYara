
rule Virus_Win32_Evaman{
	meta:
		description = "Virus:Win32/Evaman,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 0b 00 00 "
		
	strings :
		$a_00_0 = {4d 79 4e 61 6d 65 49 73 45 76 61 } //2 MyNameIsEva
		$a_00_1 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 \CurrentVersion\Run
		$a_00_2 = {5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //1 \Internet Account Manager\Accounts
		$a_00_3 = {61 65 69 6f 75 62 63 64 66 67 68 6a 6b 6c 6d 6e 70 71 72 73 74 76 77 78 79 7a } //1 aeioubcdfghjklmnpqrstvwxyz
		$a_01_4 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //1 InternetGetConnectedState
		$a_00_5 = {68 74 74 70 3a 2f 2f 65 6d 61 69 6c 2e 70 65 6f 70 6c 65 2e 79 61 68 6f 6f 2e 63 6f 6d 3a 38 30 2f 70 79 2f 70 73 53 65 61 72 63 68 2e 70 79 3f 46 69 72 73 74 4e 61 6d 65 3d } //2 http://email.people.yahoo.com:80/py/psSearch.py?FirstName=
		$a_00_6 = {50 61 74 72 69 63 69 61 40 } //1 Patricia@
		$a_00_7 = {2d 2d 2d 2d 3d 5f 4e 65 78 74 50 61 72 74 5f 25 63 5f 25 63 5f 25 64 5f 25 63 5f 25 63 5f } //1 ----=_NextPart_%c_%c_%d_%c_%c_
		$a_00_8 = {6d 78 2e 25 73 } //1 mx.%s
		$a_00_9 = {73 6d 74 70 2e 6d 61 69 6c 2e 25 73 } //1 smtp.mail.%s
		$a_00_10 = {44 6e 73 51 75 65 72 79 5f 41 } //1 DnsQuery_A
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*2+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=6
 
}
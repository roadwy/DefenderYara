
rule Trojan_Win64_GhostRat_AMB_MTB{
	meta:
		description = "Trojan:Win64/GhostRat.AMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0c 00 00 "
		
	strings :
		$a_80_0 = {61 48 52 30 63 44 6f 76 4c 7a 49 77 4e 69 34 78 4d 54 6b 75 4d 54 63 30 4c 6a 45 31 4f 6a 63 34 4e 54 67 76 59 53 35 6b 59 58 51 } //aHR0cDovLzIwNi4xMTkuMTc0LjE1Ojc4NTgvYS5kYXQ  3
		$a_80_1 = {61 48 52 30 63 44 6f 76 4c 7a 49 77 4e 79 34 31 4e 69 34 78 4f 43 34 30 4d 7a 6f 33 4f 44 55 34 4c 32 45 75 5a 47 46 30 } //aHR0cDovLzIwNy41Ni4xOC40Mzo3ODU4L2EuZGF0  3
		$a_80_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //CheckRemoteDebuggerPresent  1
		$a_80_3 = {66 61 6b 65 5f 65 6e 63 72 79 70 74 69 6f 6e 5f 6b 65 79 5f 31 32 33 34 35 } //fake_encryption_key_12345  1
		$a_80_4 = {66 61 6b 65 5f 64 61 74 61 5f 66 6f 72 5f 68 61 73 68 69 6e 67 } //fake_data_for_hashing  1
		$a_80_5 = {69 6d 6d 75 6e 69 74 79 64 65 62 75 67 67 65 72 2e 65 78 65 } //immunitydebugger.exe  1
		$a_80_6 = {74 65 6d 70 5f 64 61 74 61 2e 6c 6f 67 } //temp_data.log  1
		$a_80_7 = {76 6d 77 61 72 65 75 73 65 72 2e 65 78 65 } //vmwareuser.exe  1
		$a_80_8 = {78 65 6e 73 65 72 76 69 63 65 2e 65 78 65 } //xenservice.exe  1
		$a_80_9 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } //ollydbg.exe  1
		$a_80_10 = {43 3a 5c 68 64 2e 65 78 65 } //C:\hd.exe  1
		$a_80_11 = {73 61 6e 64 62 6f 78 } //sandbox  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=16
 
}
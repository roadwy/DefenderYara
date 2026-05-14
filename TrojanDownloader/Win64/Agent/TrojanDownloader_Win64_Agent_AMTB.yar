
rule TrojanDownloader_Win64_Agent_AMTB{
	meta:
		description = "TrojanDownloader:Win64/Agent!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 73 68 69 65 6c 64 67 75 61 72 64 76 70 6e 2e 70 72 6f 2f 76 70 6e 2f 75 70 64 61 74 65 73 2f 73 74 61 62 6c 65 2e 7a 69 70 } //https://shieldguardvpn.pro/vpn/updates/stable.zip  6
		$a_80_1 = {51 28 52 28 53 28 54 31 55 31 56 44 57 45 58 45 59 45 5a 45 5b 45 5c 45 5d 4a 5e 4a 5f 4a 60 4a 61 4a 62 4a 63 4a 64 4a 65 4a 66 4a 67 4a 68 4a } //Q(R(S(T1U1VDWEXEYEZE[E\E]J^J_J`JaJbJcJdJeJfJgJhJ  6
	condition:
		((#a_80_0  & 1)*6+(#a_80_1  & 1)*6) >=6
 
}
rule TrojanDownloader_Win64_Agent_AMTB_2{
	meta:
		description = "TrojanDownloader:Win64/Agent!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 07 00 00 "
		
	strings :
		$a_80_0 = {74 61 73 6b 68 6f 73 74 77 2e 70 61 67 65 73 2e 64 65 76 } //taskhostw.pages.dev  5
		$a_80_1 = {6d 65 74 65 72 70 72 65 74 65 72 } //meterpreter  4
		$a_80_2 = {62 65 61 63 6f 6e } //beacon  4
		$a_80_3 = {70 61 79 6c 6f 61 64 } //payload  3
		$a_80_4 = {69 6e 6a 65 63 74 } //inject  3
		$a_80_5 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //SeDebugPrivilege  3
		$a_80_6 = {73 68 65 6c 6c 63 6f 64 65 } //shellcode  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*4+(#a_80_2  & 1)*4+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*1) >=20
 
}
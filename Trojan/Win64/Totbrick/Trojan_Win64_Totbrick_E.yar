
rule Trojan_Win64_Totbrick_E{
	meta:
		description = "Trojan:Win64/Totbrick.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 20 00 49 00 4e 00 20 00 44 00 4f 00 4d 00 41 00 49 00 4e 00 2a 00 2a 00 2a 00 2a 00 } //1 MACHINE IN DOMAIN****
		$a_01_1 = {4c 00 44 00 41 00 50 00 3a 00 2f 00 2f 00 25 00 6c 00 73 00 } //1 LDAP://%ls
		$a_01_2 = {25 00 73 00 20 00 2d 00 20 00 4e 00 4f 00 54 00 20 00 56 00 55 00 4c 00 4e 00 45 00 52 00 41 00 42 00 4c 00 45 00 } //1 %s - NOT VULNERABLE
		$a_01_3 = {29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f } //1 ).DownloadFile('http://
		$a_01_4 = {4d 61 63 68 69 6e 65 46 69 6e 64 65 72 00 6e 65 74 73 63 61 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
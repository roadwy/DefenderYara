
rule Trojan_Win32_PSWZbot_UR_MTB{
	meta:
		description = "Trojan:Win32/PSWZbot.UR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {77 74 6e 67 2e 65 78 65 } //wtng.exe  1
		$a_01_1 = {40 64 72 77 73 34 } //1 @drws4
		$a_80_2 = {70 63 73 77 73 2e 65 78 65 } //pcsws.exe  1
		$a_01_3 = {48 54 54 50 2f 31 2e 31 } //1 HTTP/1.1
		$a_01_4 = {68 4e 50 56 44 48 4b 62 48 5c 4e } //1 hNPVDHKbH\N
		$a_01_5 = {47 7a 70 63 67 70 60 76 40 5c 6e 6f 5c 78 6e 7a 48 6a 71 5b 53 6e 64 77 7b 6c 7c 6a 54 44 63 68 46 5a 45 58 56 45 } //1 Gzpcgp`v@\no\xnzHjq[Sndw{l|jTDchFZEXVE
		$a_80_6 = {6d 69 63 72 73 6f 6c 76 } //micrsolv  1
		$a_80_7 = {62 61 6e 6b 6d 61 6e } //bankman  1
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}
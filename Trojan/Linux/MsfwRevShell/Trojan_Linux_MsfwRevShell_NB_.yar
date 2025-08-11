
rule Trojan_Linux_MsfwRevShell_NB_{
	meta:
		description = "Trojan:Linux/MsfwRevShell.NB!!MsfwRevShell.gen!NB,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 31 09 6a 99 58 10 b6 89 48 4d d6 c9 31 22 6a 5a 41 07 6a 0f 5a 48 05 c0 85 51 78 0a 6a 59 41 6a 50 58 29 6a 99 5f 02 01 6a 0f 5e 48 05 c0 85 3b 78 97 48 b9 48 00 02 } //2
		$a_01_1 = {48 51 e6 89 10 6a 6a 5a 58 2a 05 0f 48 59 c0 85 25 79 ff 49 74 c9 57 18 23 6a 6a 58 6a 00 48 05 e7 89 31 48 0f f6 59 05 5f 59 85 48 79 c0 6a c7 58 3c 01 6a 0f 5f 5e 05 7e 6a 0f 5a 48 05 c0 85 ed 78 e6 ff } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}

rule Trojan_Linux_MsfwRevShell_NA_{
	meta:
		description = "Trojan:Linux/MsfwRevShell.NA!!MsfwRevShell.gen!NA,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 ff 6a 09 58 99 b6 10 48 89 d6 4d 31 c9 6a 22 41 5a 6a 07 5a 0f 05 48 85 c0 78 51 6a 0a 41 59 50 6a 29 58 99 6a 02 5f 6a 01 5e 0f 05 48 85 c0 78 3b 48 97 48 b9 02 00 } //2
		$a_01_1 = {51 48 89 e6 6a 10 5a 6a 2a 58 0f 05 59 48 85 c0 79 25 49 ff c9 74 18 57 6a 23 58 6a 00 6a 05 48 89 e7 48 31 f6 0f 05 59 59 5f 48 85 c0 79 c7 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
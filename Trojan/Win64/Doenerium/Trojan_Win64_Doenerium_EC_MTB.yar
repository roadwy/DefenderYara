
rule Trojan_Win64_Doenerium_EC_MTB{
	meta:
		description = "Trojan:Win64/Doenerium.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 33 32 64 65 63 72 79 70 74 2e 70 64 62 } //7 win32decrypt.pdb
		$a_01_1 = {6d 61 78 69 6d 75 6d 70 73 77 64 2e 70 64 62 } //7 maximumpswd.pdb
		$a_01_2 = {49 8b 3f 49 8b f4 48 2b f1 48 c1 fe 03 8b ce 48 8b 04 ca 48 c1 e8 3f 83 f0 01 89 45 d0 } //10
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*7+(#a_01_2  & 1)*10) >=17
 
}
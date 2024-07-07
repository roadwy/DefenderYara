
rule Trojan_Win64_CobaltStrikeLoader_LKAB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeLoader.LKAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 40 48 8b c8 } //1
		$a_01_1 = {4c 8d 8c 24 80 01 00 00 41 b8 00 10 00 00 48 8d 94 24 60 03 00 00 48 8b 4c 24 50 } //1
		$a_01_2 = {74 65 73 74 31 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 64 6f 77 6e 6c 6f 61 64 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 64 6f 77 6e 6c 6f 61 64 2e 70 64 62 } //1 test1\source\repos\download\x64\Release\download.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
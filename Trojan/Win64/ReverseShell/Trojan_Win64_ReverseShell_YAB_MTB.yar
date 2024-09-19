
rule Trojan_Win64_ReverseShell_YAB_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 5f 61 70 70 5f 72 65 76 65 72 73 65 73 68 65 6c 6c 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 32 5f 61 70 70 5f 72 65 76 65 72 73 65 73 68 65 6c 6c 2e 70 64 62 } //1 2_app_reverseshell\x64\Release\2_app_reverseshell.pdb
		$a_01_1 = {32 00 5f 00 61 00 70 00 70 00 5f 00 72 00 65 00 76 00 65 00 72 00 73 00 65 00 73 00 68 00 65 00 6c 00 6c 00 2c 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 31 00 2e 00 30 00 } //1 2_app_reverseshell, Version 1.0
		$a_01_2 = {4d 00 59 00 32 00 41 00 50 00 50 00 52 00 45 00 56 00 45 00 52 00 53 00 45 00 53 00 48 00 45 00 4c 00 4c 00 } //1 MY2APPREVERSESHELL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
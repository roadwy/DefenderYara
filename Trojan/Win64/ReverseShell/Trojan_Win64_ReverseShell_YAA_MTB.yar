
rule Trojan_Win64_ReverseShell_YAA_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 5f 72 65 76 65 72 73 65 5f 73 68 65 6c 6c 5f 75 6e 64 65 74 65 63 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 33 5f 72 65 76 65 72 73 65 5f 73 68 65 6c 6c 5f 75 6e 64 65 74 65 63 74 2e 70 64 62 } //1 3_reverse_shell_undetect\x64\Release\3_reverse_shell_undetect.pdb
		$a_01_1 = {c7 85 10 02 00 00 31 39 32 2e 48 8d 95 e0 01 00 00 c7 85 14 02 00 00 31 36 38 2e 48 8d 8d 10 02 00 00 c7 85 18 02 00 00 38 2e 31 30 f3 0f 7f 45 20 66 c7 85 1c 02 00 00 30 00 } //1
		$a_01_2 = {c7 85 b0 02 00 00 43 72 65 61 48 8b c8 c7 85 b4 02 00 00 74 65 50 72 48 8b d8 c7 85 b8 02 00 00 6f 63 65 73 66 c7 85 bc 02 00 00 73 57 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
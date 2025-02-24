
rule Trojan_Win64_ShellCodeLoadz_A_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeLoadz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 89 6c 24 30 48 83 ca 07 48 8b 69 18 48 89 7c 24 28 4c 89 64 24 20 45 33 e4 48 3b d3 77 40 48 8b cd 48 8b c3 48 d1 e9 48 2b c1 48 3b e8 } //1
		$a_81_1 = {53 68 65 6c 6c 63 6f 64 65 } //1 Shellcode
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
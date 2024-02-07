
rule Trojan_Win64_ShellRunner_JL_MTB{
	meta:
		description = "Trojan:Win64/ShellRunner.JL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 63 6f 64 65 2e 64 6c 6c } //01 00  shellcode.dll
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 73 68 65 6c 6c 63 6f 64 65 2e 64 6c 6c } //01 00  Failed to load shellcode.dll
		$a_01_2 = {52 75 6e 54 68 61 74 53 68 69 74 } //01 00  RunThatShit
		$a_01_3 = {00 02 00 00 d0 14 00 00 00 10 00 00 00 00 00 40 01 00 00 00 00 10 } //00 00 
	condition:
		any of ($a_*)
 
}
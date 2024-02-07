
rule Trojan_MacOS_Poseidon_A{
	meta:
		description = "Trojan:MacOS/Poseidon.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 83 ec 28 48 89 6c 24 20 48 8d 6c 24 20 48 8b 44 24 30 48 89 04 24 48 8b 44 24 38 48 89 44 24 08 48 c7 44 24 10 01 00 00 00 e8 52 6a 00 00 } //01 00 
		$a_01_1 = {70 77 5f 73 68 65 6c 6c } //01 00  pw_shell
		$a_01_2 = {53 68 65 6c 6c 63 6f 64 65 } //01 00  Shellcode
		$a_01_3 = {73 68 65 6c 6c 2e 53 68 65 6c 6c } //00 00  shell.Shell
	condition:
		any of ($a_*)
 
}
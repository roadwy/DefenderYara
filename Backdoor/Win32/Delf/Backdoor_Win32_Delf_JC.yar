
rule Backdoor_Win32_Delf_JC{
	meta:
		description = "Backdoor:Win32/Delf.JC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 6c 63 6f 6d 65 20 74 6f 20 59 57 53 68 65 6c 6c 20 53 65 72 76 65 72 2e 0d 0a 50 72 65 73 73 20 45 6e 74 65 72 20 74 6f 20 73 74 61 72 74 } //01 00 
		$a_01_1 = {89 c7 b8 00 00 00 00 0f a2 89 d8 87 d9 b9 04 00 00 00 aa c1 e8 08 e2 fa 89 d0 b9 04 00 00 00 aa c1 e8 08 e2 fa 89 d8 b9 04 00 00 00 aa c1 e8 08 e2 fa 5f 5b c3 } //00 00 
	condition:
		any of ($a_*)
 
}
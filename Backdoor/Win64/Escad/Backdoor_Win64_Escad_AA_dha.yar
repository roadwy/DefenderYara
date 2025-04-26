
rule Backdoor_Win64_Escad_AA_dha{
	meta:
		description = "Backdoor:Win64/Escad.AA!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4b 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 48 00 61 00 63 00 6b 00 65 00 72 00 32 00 00 00 } //1
		$a_01_1 = {5c 6b 70 68 2e 73 79 73 00 } //1
		$a_01_2 = {7a 61 77 71 2e 62 61 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
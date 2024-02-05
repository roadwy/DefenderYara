
rule Backdoor_Linux_Getshell_F_MTB{
	meta:
		description = "Backdoor:Linux/Getshell.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 00 00 07 00 00 00 00 10 00 00 31 db 53 43 53 6a 02 6a 66 58 } //01 00 
		$a_01_1 = {cd 80 66 81 7f 02 8f ec 75 f1 5b 6a 02 59 b0 3f cd 80 49 79 f9 } //01 00 
		$a_01_2 = {6a 3c 58 6a 01 5f 0f 05 6a 10 5a e8 10 00 00 00 88 e4 bb 86 70 51 4f cb b8 f1 d9 e5 9e 56 2f 0c 5e 48 31 c0 48 ff c0 0f 05 eb d5 } //00 00 
	condition:
		any of ($a_*)
 
}
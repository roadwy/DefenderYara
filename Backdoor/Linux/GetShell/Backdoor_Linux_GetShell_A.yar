
rule Backdoor_Linux_GetShell_A{
	meta:
		description = "Backdoor:Linux/GetShell.A,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 66 58 89 e1 cd 80 97 5b 68 90 02 08 66 68 1f 91 66 53 89 e1 6a 66 90 00 } //01 00 
		$a_01_1 = {89 e1 43 cd 80 5b 99 b6 0c b0 03 cd 80 } //00 00 
	condition:
		any of ($a_*)
 
}
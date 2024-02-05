
rule Backdoor_Linux_Getshell_H_MTB{
	meta:
		description = "Backdoor:Linux/Getshell.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 00 03 00 01 00 00 00 54 80 04 08 34 00 00 00 00 00 00 00 00 00 00 00 34 00 20 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08 00 80 04 08 b3 00 00 00 12 01 00 00 07 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
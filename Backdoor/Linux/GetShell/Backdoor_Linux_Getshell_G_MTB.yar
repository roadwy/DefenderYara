
rule Backdoor_Linux_Getshell_G_MTB{
	meta:
		description = "Backdoor:Linux/Getshell.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 02 00 03 00 01 00 00 00 54 80 04 08 34 00 00 00 00 00 00 00 00 00 00 00 34 00 20 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08 00 80 04 08 dd 01 00 00 66 03 00 00 07 00 00 00 00 10 } //00 00 
	condition:
		any of ($a_*)
 
}
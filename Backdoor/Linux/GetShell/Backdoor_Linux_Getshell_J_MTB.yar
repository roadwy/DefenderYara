
rule Backdoor_Linux_Getshell_J_MTB{
	meta:
		description = "Backdoor:Linux/Getshell.J!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {6a 3b 58 99 48 bb 2f 62 69 6e 2f 73 68 00 53 48 89 e7 68 2d 63 00 00 48 89 e6 52 e8 e9 00 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
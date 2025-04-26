
rule Backdoor_Linux_GetShell_K_MTB{
	meta:
		description = "Backdoor:Linux/GetShell.K!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {80 04 08 00 80 04 08 56 01 00 00 58 02 00 00 07 00 00 00 00 10 00 00 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
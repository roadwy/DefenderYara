
rule Backdoor_Linux_GetShell_C_MTB{
	meta:
		description = "Backdoor:Linux/GetShell.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 00 03 00 01 00 00 00 54 80 04 08 34 00 00 00 00 00 00 00 00 00 00 00 34 00 20 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08 00 80 04 08 ea 00 00 00 80 01 00 00 07 00 00 00 00 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}

rule Backdoor_Linux_GetShell_I_MTB{
	meta:
		description = "Backdoor:Linux/GetShell.I!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {6d 65 74 61 73 70 6c 6f 69 74 3a 41 7a 2f 64 49 73 6a 34 70 34 49 52 63 3a 30 3a 30 3a 3a 2f 3a 2f 62 69 6e 2f 73 68 } //1 metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
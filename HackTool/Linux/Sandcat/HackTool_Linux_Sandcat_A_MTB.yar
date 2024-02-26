
rule HackTool_Linux_Sandcat_A_MTB{
	meta:
		description = "HackTool:Linux/Sandcat.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_00_0 = {2f 73 61 6e 64 63 61 74 2e 67 6f } //01 00  /sandcat.go
		$a_00_1 = {76 69 63 74 69 6d 73 69 7a 65 } //01 00  victimsize
		$a_00_2 = {2f 70 61 79 6c 6f 61 64 2e 67 6f } //00 00  /payload.go
	condition:
		any of ($a_*)
 
}
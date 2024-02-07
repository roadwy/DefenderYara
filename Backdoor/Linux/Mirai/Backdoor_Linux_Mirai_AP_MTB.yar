
rule Backdoor_Linux_Mirai_AP_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 44 6f 53 20 53 74 61 72 74 65 64 } //01 00  DDoS Started
		$a_00_1 = {68 74 74 70 20 66 6c 6f 6f 64 } //01 00  http flood
		$a_00_2 = {46 61 69 6c 65 64 20 74 6f 20 73 65 74 20 49 50 5f 48 44 52 49 4e 43 4c 2e 20 41 62 6f 72 74 69 6e 67 } //01 00  Failed to set IP_HDRINCL. Aborting
		$a_00_3 = {43 61 6e 6e 6f 74 20 73 65 6e 64 20 44 4e 53 20 66 6c 6f 6f 64 20 77 69 74 68 6f 75 74 20 61 20 64 6f 6d 61 69 6e } //01 00  Cannot send DNS flood without a domain
		$a_00_4 = {5b 76 65 67 61 2f 74 61 62 6c 65 5d 20 74 72 69 65 64 20 74 6f 20 61 63 63 65 73 73 20 74 61 62 6c 65 2e 25 64 20 62 75 74 20 69 74 20 69 73 20 6c 6f 63 6b 65 64 } //00 00  [vega/table] tried to access table.%d but it is locked
	condition:
		any of ($a_*)
 
}
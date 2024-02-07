
rule Trojan_WinNT_Octosca_PB_MTB{
	meta:
		description = "Trojan:WinNT/Octosca.PB!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4f 63 74 6f 70 75 73 20 53 63 61 6e 6e 65 72 20 2d 20 76 65 72 } //01 00  Octopus Scanner - ver
		$a_00_1 = {45 6e 75 6d 65 72 61 74 69 6e 67 20 6f 70 65 6e 65 64 20 70 72 6f 6a 65 63 74 73 } //01 00  Enumerating opened projects
		$a_00_2 = {6e 65 77 57 61 74 63 68 53 65 72 76 69 63 65 } //01 00  newWatchService
		$a_00_3 = {6f 63 74 6f 70 75 73 2f 4f 63 74 6f 70 75 73 } //01 00  octopus/Octopus
		$a_00_4 = {6f 70 65 6e 50 72 6f 6a 65 63 74 73 55 52 4c 73 } //00 00  openProjectsURLs
	condition:
		any of ($a_*)
 
}
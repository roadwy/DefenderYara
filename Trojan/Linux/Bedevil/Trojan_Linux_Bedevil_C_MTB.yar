
rule Trojan_Linux_Bedevil_C_MTB{
	meta:
		description = "Trojan:Linux/Bedevil.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6c 73 72 6f 6f 74 6b 69 74 } //01 00  lsrootkit
		$a_00_1 = {77 72 69 74 65 62 61 73 68 72 63 } //01 00  writebashrc
		$a_00_2 = {62 64 76 70 72 65 70 } //00 00  bdvprep
	condition:
		any of ($a_*)
 
}
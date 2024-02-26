
rule Trojan_BAT_Barys_SG_MTB{
	meta:
		description = "Trojan:BAT/Barys.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 4c 5f 41 6e 64 5f 50 5f 52 54 4b } //01 00  DL_And_P_RTK
		$a_01_1 = {4e 77 5f 45 54 5f 50 } //01 00  Nw_ET_P
		$a_00_2 = {57 46 41 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  WFA1.Properties.Resources.resources
	condition:
		any of ($a_*)
 
}
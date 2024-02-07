
rule Trojan_O97M_Donoff_ARC_MTB{
	meta:
		description = "Trojan:O97M/Donoff.ARC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 42 5f 4e 61 6d 65 20 3d 20 22 43 30 31 5f 57 48 22 } //01 00  VB_Name = "C01_WH"
		$a_01_1 = {52 65 6d 20 43 61 6c 6c 20 58 58 58 5f 56 62 61 52 65 6d 6f 76 65 2e 44 65 6c 65 74 65 56 42 41 } //00 00  Rem Call XXX_VbaRemove.DeleteVBA
	condition:
		any of ($a_*)
 
}
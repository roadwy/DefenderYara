
rule Trojan_O97M_Obfuse_YD_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.YD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {2e 41 64 64 72 65 73 73 28 30 2c 20 30 29 22 3a 20 90 02 10 20 3d 20 53 68 65 6c 6c 28 90 00 } //01 00 
		$a_00_1 = {41 70 70 6c 49 63 61 74 69 6f 6e 2e 51 75 69 74 } //00 00  ApplIcation.Quit
	condition:
		any of ($a_*)
 
}
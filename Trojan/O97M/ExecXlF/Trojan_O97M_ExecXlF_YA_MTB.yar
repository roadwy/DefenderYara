
rule Trojan_O97M_ExecXlF_YA_MTB{
	meta:
		description = "Trojan:O97M/ExecXlF.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 52 65 70 6c 61 63 65 28 55 73 65 72 46 6f 72 6d 90 02 02 2e 54 65 78 74 42 6f 78 90 02 02 2e 54 65 78 74 90 00 } //01 00 
		$a_00_1 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 28 22 65 78 65 63 28 22 22 43 4d 44 } //00 00 
	condition:
		any of ($a_*)
 
}
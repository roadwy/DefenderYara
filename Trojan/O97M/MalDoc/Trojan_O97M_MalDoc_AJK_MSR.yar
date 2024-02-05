
rule Trojan_O97M_MalDoc_AJK_MSR{
	meta:
		description = "Trojan:O97M/MalDoc.AJK!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {31 38 34 7a 7a 7a 2e 31 36 34 7a 7a 7a 2e 31 34 36 7a 7a 7a 2e 31 30 32 } //01 00 
		$a_00_1 = {53 70 6c 69 74 28 6d 65 72 65 6e 67 65 2c 20 22 7a 7a 7a 22 29 } //01 00 
		$a_00_2 = {63 6d 64 20 6b 6b 6b 2f 43 20 6b 6b 6b 65 78 65 6b 6b 6b 66 69 6e 67 65 72 6b 6b 6b 25 61 70 70 64 61 74 61 25 } //01 00 
		$a_00_3 = {63 65 72 74 75 74 69 6c 6f 6f 6f 20 2d 64 65 63 6f 64 65 } //01 00 
		$a_00_4 = {53 70 6c 69 74 28 61 72 65 6e 61 2c 20 22 6f 6f 6f 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
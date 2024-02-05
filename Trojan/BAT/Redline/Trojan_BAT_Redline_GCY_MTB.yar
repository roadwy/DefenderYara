
rule Trojan_BAT_Redline_GCY_MTB{
	meta:
		description = "Trojan:BAT/Redline.GCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 66 73 64 6b 66 64 68 67 66 73 68 73 65 66 66 64 66 61 66 66 68 66 64 63 68 } //01 00 
		$a_01_1 = {5a 6b 46 77 5a 47 31 77 62 58 42 6b 53 57 52 42 62 51 3d 3d } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}
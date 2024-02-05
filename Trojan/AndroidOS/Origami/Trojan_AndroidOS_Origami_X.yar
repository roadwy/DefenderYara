
rule Trojan_AndroidOS_Origami_X{
	meta:
		description = "Trojan:AndroidOS/Origami.X,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 33 56 30 52 32 39 70 62 6d 63 67 } //01 00 
		$a_01_1 = {53 57 35 6a 62 32 31 70 62 6d 63 67 } //01 00 
		$a_01_2 = {59 4f 55 52 20 54 45 58 54 20 48 45 52 45 } //01 00 
		$a_01_3 = {64 6e 65 77 63 61 6c 6c 69 6e 67 66 } //01 00 
		$a_01_4 = {52 65 6d 6f 76 65 69 6e 67 20 66 69 6c 65 73 } //01 00 
		$a_01_5 = {59 57 52 6b 63 6d 56 7a 63 77 } //01 00 
		$a_01_6 = {59 6d 39 6b 65 51 3d 3d } //00 00 
	condition:
		any of ($a_*)
 
}
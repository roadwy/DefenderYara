
rule Trojan_AndroidOS_Triada_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Triada.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 6f 6b 64 64 6c 69 6f } //01 00 
		$a_00_1 = {2f 61 70 70 2f 64 64 2f 61 70 70 58 43 68 61 6e 6e 65 6c } //01 00 
		$a_00_2 = {64 64 6c 65 61 64 2f 64 61 74 61 55 70 64 61 74 65 2e 70 6e 67 } //01 00 
		$a_00_3 = {52 75 6e 6e 69 6e 67 54 61 73 6b 49 6e 66 6f } //01 00 
		$a_00_4 = {67 65 74 6d 69 6d 65 74 79 70 65 66 72 6f 6d 65 78 74 65 6e 73 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
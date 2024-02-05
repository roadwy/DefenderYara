
rule Trojan_AndroidOS_Golf_A{
	meta:
		description = "Trojan:AndroidOS/Golf.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {69 6e 20 53 65 6c 66 4b 69 6c 6c 65 72 20 6b 69 6c 6c } //02 00 
		$a_00_1 = {43 61 6d 65 72 61 20 66 69 6c 65 20 73 61 76 65 64 } //02 00 
		$a_00_2 = {67 65 74 43 61 6c 6c 4c 6f 67 4c 69 73 74 } //02 00 
		$a_00_3 = {67 6f 69 6e 67 20 74 6f 20 72 65 63 6f 72 64 20 76 69 64 65 6f } //00 00 
	condition:
		any of ($a_*)
 
}
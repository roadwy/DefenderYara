
rule Trojan_AndroidOS_Basbanke_C{
	meta:
		description = "Trojan:AndroidOS/Basbanke.C,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {78 41 63 63 65 73 73 69 62 69 6c 69 4d 61 73 74 65 72 7a 69 6e 68 6f } //02 00 
		$a_00_1 = {73 74 61 72 74 65 72 74 77 6f 5f 42 52 } //02 00 
		$a_00_2 = {78 41 72 6d 61 7a 65 6e 61 45 76 65 6e 74 6f 41 63 63 65 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_AndroidOS_Congur_A{
	meta:
		description = "Trojan:AndroidOS/Congur.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {56 69 72 75 73 53 65 72 76 69 63 65 24 31 30 30 30 30 30 30 30 30 } //01 00 
		$a_01_1 = {76 65 69 6c 5f 6c 69 66 74 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}
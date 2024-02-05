
rule Trojan_AndroidOS_Banker_P{
	meta:
		description = "Trojan:AndroidOS/Banker.P,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 52 65 63 76 55 73 65 72 74 46 69 6c 74 65 72 } //01 00 
		$a_01_1 = {64 6f 4d 4d 53 74 68 72 65 61 64 } //01 00 
		$a_00_2 = {42 6c 6f 63 6b 48 61 72 64 77 61 72 65 42 75 74 74 6f 6e 73 } //00 00 
	condition:
		any of ($a_*)
 
}
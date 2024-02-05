
rule Trojan_AndroidOS_Rainbowrat_A{
	meta:
		description = "Trojan:AndroidOS/Rainbowrat.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 6d 69 63 72 6f 70 68 6f 6e 65 52 65 63 6f 72 64 46 69 6c 65 } //01 00 
		$a_01_1 = {57 78 42 63 6d 31 35 41 6b 6e 73 64 6b 6c 41 53 6b 44 53 32 31 33 39 6a 53 63 6e 6f 33 46 4e 64 33 39 6e 76 6f 39 77 6e 33 39 61 73 63 6e 33 6f 39 6e 4b 44 6e 46 39 65 66 6e 44 46 4e 4f 46 44 6a } //00 00 
	condition:
		any of ($a_*)
 
}
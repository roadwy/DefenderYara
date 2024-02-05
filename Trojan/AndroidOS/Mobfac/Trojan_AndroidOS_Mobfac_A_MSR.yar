
rule Trojan_AndroidOS_Mobfac_A_MSR{
	meta:
		description = "Trojan:AndroidOS/Mobfac.A!MSR,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 69 6e 74 65 72 66 61 63 65 2e 6b 6f 6b 6d 6f 62 69 2e 63 6f 6d 2f 6e 65 77 73 65 72 76 69 63 65 } //01 00 
		$a_00_1 = {2f 61 70 70 2f 6b 6f 6b 2f 54 79 70 65 43 68 61 6e 6e 65 6c } //01 00 
		$a_00_2 = {2f 61 70 70 2f 6b 6f 6b 2f 61 70 70 43 68 61 6e 6e 65 6c } //01 00 
		$a_00_3 = {2f 6e 65 77 62 61 63 6b 44 61 74 61 73 2e 61 63 74 69 6f 6e } //01 00 
		$a_00_4 = {2f 6e 65 77 67 65 74 41 70 6b 73 2e 61 63 74 69 6f 6e } //01 00 
		$a_00_5 = {2f 6e 65 77 6a 73 41 70 6b 2e 61 63 74 69 6f 6e } //01 00 
		$a_00_6 = {2f 6e 65 77 6f 70 65 6e 4f 72 53 61 6c 65 2e 61 63 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
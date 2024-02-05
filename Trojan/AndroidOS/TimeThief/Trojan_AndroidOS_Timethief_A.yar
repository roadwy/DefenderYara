
rule Trojan_AndroidOS_Timethief_A{
	meta:
		description = "Trojan:AndroidOS/Timethief.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 66 75 6e 61 70 70 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 3b } //02 00 
		$a_00_1 = {59 6f 75 20 68 61 76 65 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 72 65 67 69 73 74 65 72 65 64 20 75 73 65 20 50 72 65 76 20 61 6e 64 20 4e 65 78 74 20 62 75 74 74 6f 6e 73 2e 20 45 6e 6a 6f 79 20 77 69 74 68 20 74 68 65 20 66 75 6e 20 50 69 63 74 75 72 65 73 2e 2e 2e } //00 00 
	condition:
		any of ($a_*)
 
}
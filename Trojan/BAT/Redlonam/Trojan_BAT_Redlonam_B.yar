
rule Trojan_BAT_Redlonam_B{
	meta:
		description = "Trojan:BAT/Redlonam.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 6f 6c 64 65 72 4e 61 6d 65 5c 66 69 6c 65 2e 65 78 65 } //01 00 
		$a_01_1 = {00 66 69 6c 65 2e 65 78 65 } //01 00 
		$a_01_2 = {5c 74 65 6d 70 5c } //01 00 
		$a_01_3 = {52 65 67 41 73 6d 2e 65 78 65 00 4d 69 63 72 6f 73 6f 66 74 20 41 63 63 65 73 73 2e 2e 2e 32 30 31 33 2e 65 78 65 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 8f 
	condition:
		any of ($a_*)
 
}
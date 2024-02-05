
rule Trojan_BAT_NjRat_NECW_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {24 66 31 36 31 31 66 66 36 2d 32 35 63 32 2d 34 37 39 62 2d 38 38 61 61 2d 63 62 35 61 38 61 39 35 66 31 31 38 } //03 00 
		$a_01_1 = {5f 30 30 37 53 74 75 62 2e 50 72 6f 70 65 72 74 69 65 73 } //03 00 
		$a_01_2 = {50 76 72 6f 69 6b 4a 6c 6c 59 } //01 00 
		$a_01_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}
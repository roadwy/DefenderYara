
rule Trojan_BAT_MSILZilla_RDC_MTB{
	meta:
		description = "Trojan:BAT/MSILZilla.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 37 36 37 44 43 44 36 2d 45 39 33 41 2d 34 41 34 39 2d 39 41 45 44 2d 41 41 31 33 34 44 32 43 41 43 39 43 } //01 00 
		$a_01_1 = {69 6e 65 74 69 6e 66 6f } //01 00 
		$a_01_2 = {62 75 4f 65 50 31 76 4a 43 66 68 64 52 54 4b 52 50 76 2e 45 59 41 6d 50 59 62 32 73 58 6b 55 78 6b 6f 6d 35 38 } //01 00 
		$a_01_3 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 } //00 00 
	condition:
		any of ($a_*)
 
}
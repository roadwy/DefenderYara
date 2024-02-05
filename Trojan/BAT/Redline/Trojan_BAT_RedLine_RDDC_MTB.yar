
rule Trojan_BAT_RedLine_RDDC_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {37 30 61 32 30 34 38 35 2d 61 33 36 66 2d 34 61 61 65 2d 62 66 33 34 2d 34 36 32 33 65 36 62 62 61 37 38 33 } //01 00 
		$a_01_1 = {43 72 65 61 6d 41 50 49 5f 43 53 68 61 72 70 } //01 00 
		$a_01_2 = {43 41 70 69 46 69 6c 65 47 65 73 74 } //01 00 
		$a_01_3 = {6d 45 71 6d 6f 45 39 55 78 52 6d 58 39 6f 67 63 74 6f } //00 00 
	condition:
		any of ($a_*)
 
}
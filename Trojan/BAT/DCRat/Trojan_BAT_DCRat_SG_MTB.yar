
rule Trojan_BAT_DCRat_SG_MTB{
	meta:
		description = "Trojan:BAT/DCRat.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 77 71 64 61 6e 63 68 75 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  qwqdanchun.Properties.Resources.resources
		$a_01_1 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_01_2 = {36 66 35 32 34 35 62 65 2d 33 37 65 63 2d 34 63 66 62 2d 38 66 36 66 2d 30 33 65 64 33 38 32 31 35 64 30 61 } //00 00  6f5245be-37ec-4cfb-8f6f-03ed38215d0a
	condition:
		any of ($a_*)
 
}
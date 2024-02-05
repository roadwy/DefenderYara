
rule Trojan_BAT_StormKitty_NEAD_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {36 36 62 61 38 63 65 32 2d 35 31 38 63 2d 34 37 33 34 2d 38 36 38 37 2d 61 63 63 32 36 61 63 34 30 33 65 39 } //02 00 
		$a_01_1 = {67 69 6c 72 66 64 69 72 35 6c 37 67 73 65 2e 65 78 65 } //02 00 
		$a_01_2 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 2b 34 34 37 33 34 31 39 36 34 66 } //02 00 
		$a_01_3 = {44 65 63 72 79 70 74 } //02 00 
		$a_01_4 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}
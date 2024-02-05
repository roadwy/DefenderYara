
rule Trojan_BAT_Redline_NEAM_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {31 61 62 64 32 39 33 38 2d 62 35 61 62 2d 34 36 30 37 2d 39 37 61 65 2d 38 33 30 38 62 32 36 61 63 37 66 36 } //02 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 20 42 69 6f 6d 65 74 72 69 63 73 20 43 6c 69 65 6e 74 20 41 50 49 } //02 00 
		$a_01_2 = {30 2e 39 2e 38 2e 36 33 37 31 } //02 00 
		$a_01_3 = {5a 61 6d 65 74 6b 65 52 2e 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 73 } //02 00 
		$a_01_4 = {56 77 4b 4c 47 70 54 2e 43 6f 6e 73 75 6d 65 72 73 } //00 00 
	condition:
		any of ($a_*)
 
}
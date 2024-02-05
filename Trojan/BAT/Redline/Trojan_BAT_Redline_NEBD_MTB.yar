
rule Trojan_BAT_Redline_NEBD_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {62 63 64 33 63 62 65 62 2d 65 36 34 39 2d 34 38 35 66 2d 61 66 31 65 2d 33 64 38 37 38 38 31 33 38 64 66 35 } //02 00 
		$a_01_1 = {50 00 49 00 5a 00 5a 00 41 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //02 00 
		$a_01_2 = {49 00 4d 00 50 00 52 00 49 00 4d 00 49 00 45 00 4e 00 44 00 4f 00 20 00 54 00 49 00 43 00 4b 00 45 00 54 00 } //00 00 
	condition:
		any of ($a_*)
 
}
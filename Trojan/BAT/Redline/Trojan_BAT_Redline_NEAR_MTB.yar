
rule Trojan_BAT_Redline_NEAR_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {64 31 63 63 32 62 61 64 2d 64 36 66 37 2d 34 37 62 38 2d 61 66 61 38 2d 33 61 39 64 34 34 33 30 64 63 63 31 } //04 00 
		$a_01_1 = {58 4f 4e 45 2e 65 78 65 } //04 00 
		$a_01_2 = {59 4a 32 33 34 6a 38 68 54 5a 44 35 39 50 6f 4f } //04 00 
		$a_01_3 = {48 54 7a 75 7a 41 53 62 4a 6e 6d 72 6c 45 67 64 52 66 45 51 48 } //00 00 
	condition:
		any of ($a_*)
 
}
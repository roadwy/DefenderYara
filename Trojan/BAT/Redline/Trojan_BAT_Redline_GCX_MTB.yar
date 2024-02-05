
rule Trojan_BAT_Redline_GCX_MTB{
	meta:
		description = "Trojan:BAT/Redline.GCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 00 06 18 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 06 6f 90 01 03 0a 0b 02 28 90 01 03 06 0c 07 08 16 08 8e 69 6f 90 01 03 0a 0d 09 13 04 2b 00 11 04 2a 90 00 } //01 00 
		$a_01_1 = {39 00 4a 00 5a 00 77 00 45 00 65 00 6d 00 4e 00 66 00 65 00 6d 00 41 00 77 00 6f 00 51 00 44 00 4b 00 54 00 7a 00 30 00 46 00 77 00 3d 00 3d 00 } //01 00 
		$a_01_2 = {43 6f 6e 63 65 6e 37 72 61 37 65 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_XWorm_GCD_MTB{
	meta:
		description = "Trojan:BAT/XWorm.GCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {fe 09 05 00 20 26 35 b2 04 26 26 fe 09 04 00 20 35 6a 07 00 26 26 73 04 00 00 0a fe 0e 00 00 fe 09 00 00 6f 90 01 03 0a fe 0e 01 00 20 00 00 00 00 fe 0e 02 00 2b 2f fe 0c 01 00 fe 0c 02 00 93 fe 0e 03 00 fe 0c 00 00 fe 0c 03 00 fe 09 02 00 59 d1 90 00 } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 } //01 00 
		$a_01_2 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}

rule Trojan_BAT_Redline_NRZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.NRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {20 6d 11 5d 34 0a 02 28 90 01 03 06 28 90 01 03 0a 06 20 90 01 03 cb 58 28 90 01 03 0a 2a 90 00 } //01 00 
		$a_01_1 = {51 6f 36 34 47 6a } //01 00 
		$a_01_2 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 66 00 72 00 6f 00 6d 00 20 00 74 00 62 00 6c 00 5f 00 61 00 6e 00 67 00 67 00 6f 00 74 00 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}
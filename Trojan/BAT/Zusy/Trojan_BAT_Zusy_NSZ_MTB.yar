
rule Trojan_BAT_Zusy_NSZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NSZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {20 07 00 00 00 28 90 01 03 06 3a 90 01 03 ff 26 06 20 90 01 03 00 0d 12 03 6f 90 01 03 06 20 90 01 03 00 38 90 01 03 ff 00 73 90 01 03 06 0a 16 28 90 01 03 06 39 90 01 03 00 26 20 90 01 03 00 38 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {64 6f 6f 72 69 6e 62 6f 6f 6b 5f 38 34 37 32 31 34 } //00 00 
	condition:
		any of ($a_*)
 
}
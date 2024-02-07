
rule Trojan_BAT_Quasar_RF_MTB{
	meta:
		description = "Trojan:BAT/Quasar.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {1f 0f 0a 1f 0f 0b 1f 0f 0b 00 07 16 33 05 1f 0f 0b 2b 17 00 12 00 12 01 12 02 12 03 7e 90 01 04 06 97 29 90 01 04 2b df 00 2a 90 00 } //01 00 
		$a_01_1 = {24 35 66 30 64 63 63 63 38 2d 64 36 39 61 2d 34 39 66 38 2d 39 65 36 34 2d 36 31 61 65 37 37 62 66 66 34 38 66 } //01 00  $5f0dccc8-d69a-49f8-9e64-61ae77bff48f
		$a_01_2 = {47 00 72 00 61 00 73 00 79 00 61 00 79 00 2e 00 65 00 78 00 65 00 } //00 00  Grasyay.exe
	condition:
		any of ($a_*)
 
}
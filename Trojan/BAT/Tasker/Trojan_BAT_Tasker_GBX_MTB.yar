
rule Trojan_BAT_Tasker_GBX_MTB{
	meta:
		description = "Trojan:BAT/Tasker.GBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {59 65 20 2d 22 19 e9 58 20 01 00 00 00 63 20 90 01 03 0b 58 61 fe 09 00 00 61 d1 9d fe 0c 01 00 20 90 01 03 21 65 20 90 01 03 de 59 59 25 fe 0e 01 00 20 90 01 03 22 20 90 01 03 ed 59 20 90 01 03 19 59 20 90 01 03 14 59 66 20 90 01 03 07 61 20 90 01 03 ff 59 20 90 01 03 00 63 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}
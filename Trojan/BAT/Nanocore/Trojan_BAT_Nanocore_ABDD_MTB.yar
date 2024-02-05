
rule Trojan_BAT_Nanocore_ABDD_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 00 07 17 58 0b 07 20 90 01 03 00 fe 04 0c 08 2d da 06 28 90 01 03 06 26 2a 90 00 } //01 00 
		$a_01_1 = {54 00 72 00 61 00 66 00 66 00 69 00 63 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}
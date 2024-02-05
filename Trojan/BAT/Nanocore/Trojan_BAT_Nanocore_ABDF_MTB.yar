
rule Trojan_BAT_Nanocore_ABDF_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 28 56 00 00 0a 28 90 01 03 0a 0a 2b 00 06 2a 90 00 } //02 00 
		$a_03_1 = {11 04 16 91 2d 02 2b 09 09 16 9a 28 90 01 03 0a 0c 74 90 01 03 01 28 90 01 03 06 00 06 2a 90 00 } //01 00 
		$a_01_2 = {45 00 62 00 6f 00 6f 00 6b 00 73 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}
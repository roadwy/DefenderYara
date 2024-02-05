
rule Trojan_BAT_Bsymem_NBY_MTB{
	meta:
		description = "Trojan:BAT/Bsymem.NBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {20 01 09 51 15 61 20 90 01 03 2b 40 90 01 03 00 20 90 01 03 00 fe 90 01 02 00 fe 90 01 04 01 58 00 fe 90 01 02 00 8e 69 6f 90 01 03 0a fe 90 01 02 00 20 90 01 03 00 fe 90 01 02 00 20 90 01 03 00 20 90 01 03 5f 20 90 01 03 51 61 20 90 01 03 0e 90 00 } //01 00 
		$a_01_1 = {4d 6f 69 65 74 79 6b 6f 72 73 } //00 00 
	condition:
		any of ($a_*)
 
}
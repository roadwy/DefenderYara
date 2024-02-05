
rule Trojan_BAT_Tedy_NEAB_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {16 07 1f 0f 1f 10 28 5b 01 00 06 7e 08 01 00 04 06 07 28 3a 01 00 06 7e 26 01 00 04 06 18 28 5e 01 00 06 7e 0c 01 00 04 06 28 3d 01 00 06 0d 7e 28 01 00 04 09 03 16 03 8e 69 } //02 00 
		$a_01_1 = {73 00 6f 00 6d 00 65 00 72 00 61 00 6e 00 64 00 6f 00 6d 00 66 00 69 00 6c 00 65 00 } //02 00 
		$a_01_2 = {64 00 66 00 61 00 67 00 6e 00 6d 00 62 00 68 00 62 00 53 00 62 00 6d 00 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}
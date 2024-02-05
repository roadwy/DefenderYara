
rule Trojan_BAT_Shelm_RDA_MTB{
	meta:
		description = "Trojan:BAT/Shelm.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 65 61 31 61 61 38 61 2d 63 61 64 33 2d 34 36 32 30 2d 38 37 35 65 2d 37 66 36 37 38 63 63 36 37 64 32 63 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 54 68 72 65 61 64 70 6f 6f 6c 57 61 69 74 5f 53 68 65 6c 6c 63 6f 64 65 45 78 65 63 75 74 69 6f 6e } //02 00 
		$a_03_2 = {07 11 07 07 11 07 91 20 90 01 04 61 d2 9c 11 07 17 58 13 07 11 07 07 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
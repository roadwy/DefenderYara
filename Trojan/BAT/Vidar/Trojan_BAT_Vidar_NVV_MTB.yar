
rule Trojan_BAT_Vidar_NVV_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {5f 60 58 0e 07 0e 04 e0 95 58 7e 90 01 02 00 04 0e 06 17 59 e0 95 58 0e 05 28 90 01 02 00 06 58 90 00 } //01 00 
		$a_01_1 = {6d 69 63 72 6f 70 61 74 63 68 32 64 6c 6c 5f 63 6f 6d 70 6c 65 61 74 65 } //00 00  micropatch2dll_compleate
	condition:
		any of ($a_*)
 
}